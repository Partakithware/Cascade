#include <gtk/gtk.h>
#include <glib.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <thread>
#include <atomic>
#include <mutex>
#include <queue>
#include "nlohmann/json.hpp"
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <cmath> // For std::round

using json = nlohmann::json;

// Forward Declarations (Required for the new structure)
class CascadeSeeder;
class MultiPeerDownloader;

// -------------------- Structures --------------------
struct Peer { std::string ip; uint16_t port; };
struct CascadeMeta {
    std::string fileName; size_t fileSize; size_t pieceSize;
    std::vector<std::string> pieces; std::vector<Peer> peers;
    std::string cascadePath; // New: to keep track of the source file
};

// New structure to hold the *runtime state* of a single cascade for the UI
struct CascadeState {
    std::string id; // Unique ID (e.g., hash or file name)
    std::string fileName;
    std::string status; // e.g., "Downloading", "Seeding", "Complete", "Error"
    double progressFraction; // 0.0 to 1.0
    int seeds; // For display, simplified count
    std::atomic<bool> isSeeding;
    std::shared_ptr<CascadeSeeder> seeder;
    std::unique_ptr<std::thread> downloaderThread; // New: keep track of the download thread
    std::string downloadPath; // Full path to the downloaded file

    // FIX 3: Define custom move assignment operator to handle atomic and unique_ptr members
    CascadeState& operator=(CascadeState&& other) noexcept {
        if (this != &other) {
            id = std::move(other.id);
            fileName = std::move(other.fileName);
            status = std::move(other.status);
            progressFraction = other.progressFraction;
            seeds = other.seeds;
            isSeeding.store(other.isSeeding.load()); // Atomic copy
            seeder = std::move(other.seeder);
            downloaderThread = std::move(other.downloaderThread);
            downloadPath = std::move(other.downloadPath);
        }
        return *this;
    }

    // Must explicitly define move constructor if we define move assignment, or vice versa
    CascadeState(CascadeState&& other) noexcept 
        : id(std::move(other.id)), 
          fileName(std::move(other.fileName)), 
          status(std::move(other.status)), 
          progressFraction(other.progressFraction),
          seeds(other.seeds),
          isSeeding(other.isSeeding.load()), // Atomic copy
          seeder(std::move(other.seeder)),
          downloaderThread(std::move(other.downloaderThread)),
          downloadPath(std::move(other.downloadPath)) {}
    
    // Default constructor for map initialization
    CascadeState() : isSeeding(false), progressFraction(0.0), seeds(0) {}
    
    // Custom constructor for creation convenience
    CascadeState(std::string id, std::string fn, std::string st, double pf, int s, bool is, std::shared_ptr<CascadeSeeder> sd, std::unique_ptr<std::thread> dt, std::string dp) 
        : id(std::move(id)), fileName(std::move(fn)), status(std::move(st)), progressFraction(pf), seeds(s), isSeeding(is), seeder(std::move(sd)), downloaderThread(std::move(dt)), downloadPath(std::move(dp)) {}

    // Delete copy operations as recommended for types with unique_ptr/atomic
    CascadeState(const CascadeState&) = delete;
    CascadeState& operator=(const CascadeState&) = delete;

};


// Global storage for active cascades and the application data
// Note: We combine g_active_seeds into the list store logic below, 
// but keep a C++-side map for easy lookup and management.
std::mutex g_state_mutex;
std::map<std::string, CascadeState> g_active_cascades; 

// Structure to hold C++ components in the C environment
struct AppData {
    std::string download_dir;
    GListStore *cascade_list_store = NULL; // The model for the list view
    GtkWidget *list_view = NULL;           // The list view widget
};

// FIX 2 Helper: Use g_object_get_data on the GApplication object
AppData* get_app_data(GtkApplication *app) {
    if (!app) {
        // Fallback for when app is NULL, often in helper functions called by threads
        GApplication *default_app = g_application_get_default();
        return static_cast<AppData*>(g_object_get_data(G_OBJECT(default_app), "app-data"));
    }
    return static_cast<AppData*>(g_object_get_data(G_OBJECT(app), "app-data"));
}


// -------------------- UI Utility Functions (Adapted for List View) --------------------

// Custom GObject type for the list store elements (C/GTK side)
#define CASCADE_TYPE_ITEM (cascade_item_get_type())
G_DECLARE_FINAL_TYPE(CascadeItem, cascade_item, CASCADE, ITEM, GObject)

struct _CascadeItem {
    GObject parent_instance;
    char *id;
    char *fileName;
    char *status;
    double progressFraction;
    int seeds;
};

// Implementation for CascadeItem
G_DEFINE_FINAL_TYPE(CascadeItem, cascade_item, G_TYPE_OBJECT);

static void cascade_item_init(CascadeItem *self) {
    self->id = g_strdup("");
    self->fileName = g_strdup("Unknown");
    self->status = g_strdup("Initializing");
    self->progressFraction = 0.0;
    self->seeds = 0;
}

static void cascade_item_dispose(GObject *gobject) {
    CascadeItem *self = CASCADE_ITEM(gobject);
    g_free(self->id);
    g_free(self->fileName);
    g_free(self->status);
    G_OBJECT_CLASS(cascade_item_parent_class)->dispose(gobject);
}

// Property setters/getters
enum {
    PROP_0,
    PROP_ID,
    PROP_FILE_NAME,
    PROP_STATUS,
    PROP_PROGRESS_FRACTION,
    PROP_SEEDS,
    N_PROPERTIES
};

static GParamSpec *obj_properties[N_PROPERTIES] = { NULL, };

static void cascade_item_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec) {
    CascadeItem *self = CASCADE_ITEM(object);
    switch (property_id) {
        case PROP_ID:
            g_free(self->id);
            self->id = g_strdup(g_value_get_string(value));
            break;
        case PROP_FILE_NAME:
            g_free(self->fileName);
            self->fileName = g_strdup(g_value_get_string(value));
            break;
        case PROP_STATUS:
            g_free(self->status);
            self->status = g_strdup(g_value_get_string(value));
            break;
        case PROP_PROGRESS_FRACTION:
            self->progressFraction = g_value_get_double(value);
            break;
        case PROP_SEEDS:
            self->seeds = g_value_get_int(value);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
            break;
    }
}

static void cascade_item_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec) {
    CascadeItem *self = CASCADE_ITEM(object);
    switch (property_id) {
        case PROP_ID:
            g_value_set_string(value, self->id);
            break;
        case PROP_FILE_NAME:
            g_value_set_string(value, self->fileName);
            break;
        case PROP_STATUS:
            g_value_set_string(value, self->status);
            break;
        case PROP_PROGRESS_FRACTION:
            g_value_set_double(value, self->progressFraction);
            break;
        case PROP_SEEDS:
            g_value_set_int(value, self->seeds);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
            break;
    }
}

static void cascade_item_class_init(CascadeItemClass *klass) {
    GObjectClass *object_class = G_OBJECT_CLASS(klass);
    object_class->dispose = cascade_item_dispose;
    object_class->set_property = cascade_item_set_property;
    object_class->get_property = cascade_item_get_property;

    // FIX 1: Explicitly cast the flags to GParamFlags to resolve the 'invalid conversion from int' error
    GParamFlags flags = (GParamFlags)(G_PARAM_READWRITE | G_PARAM_EXPLICIT_NOTIFY);

    obj_properties[PROP_ID] = g_param_spec_string("id", "ID", "Unique ID", "", flags);
    obj_properties[PROP_FILE_NAME] = g_param_spec_string("file-name", "File Name", "Name of the file", "", flags);
    obj_properties[PROP_STATUS] = g_param_spec_string("status", "Status", "Current status", "Initializing", flags);
    obj_properties[PROP_PROGRESS_FRACTION] = g_param_spec_double("progress-fraction", "Progress Fraction", "Download/Seed Progress", 0.0, 1.0, 0.0, flags);
    obj_properties[PROP_SEEDS] = g_param_spec_int("seeds", "Seeds", "Number of seeds/peers connected", 0, 1000, 0, flags);

    g_object_class_install_properties(object_class, N_PROPERTIES, obj_properties);
}

// Helper to find CascadeItem in GListStore by ID
CascadeItem* find_cascade_item(GListStore *store, const std::string& id) {
    guint n_items = g_list_model_get_n_items(G_LIST_MODEL(store));
    for (guint i = 0; i < n_items; ++i) {
        CascadeItem *item = CASCADE_ITEM(g_list_model_get_item(G_LIST_MODEL(store), i));
        if (item && item->id && id == item->id) {
            return item;
        }
        g_object_unref(item); // Must unref if we don't return it
    }
    return nullptr;
}

// Function to safely update the UI list from background threads
void update_cascade_ui(GListStore *store, const std::string& id, const std::string& fileName, const std::string& status, double progress, int seeds = 0) {
    
    // We pass all data via a simple struct to the idle callback
    struct UpdateData {
        GListStore *store;
        std::string id;
        std::string fileName;
        std::string status;
        double progress;
        int seeds;
    };
    
    UpdateData *data = new UpdateData{
        store, id, fileName, status, progress, seeds
    };

    g_idle_add_full(G_PRIORITY_DEFAULT, [](gpointer d) -> gboolean {
        UpdateData *ud = static_cast<UpdateData*>(d);
        
        CascadeItem *item = find_cascade_item(ud->store, ud->id);

        if (item) {
            // Update existing item
            g_object_set(item, 
                         "file-name", ud->fileName.c_str(),
                         "status", ud->status.c_str(),
                         "progress-fraction", ud->progress,
                         "seeds", ud->seeds,
                         NULL);
            g_object_unref(item); // Unref the returned item after use
        } else {
            // Add new item
            item = CASCADE_ITEM(g_object_new(CASCADE_TYPE_ITEM,
                                             "id", ud->id.c_str(),
                                             "file-name", ud->fileName.c_str(),
                                             "status", ud->status.c_str(),
                                             "progress-fraction", ud->progress,
                                             "seeds", ud->seeds,
                                             NULL));
            g_list_store_append(ud->store, G_OBJECT(item));
            g_object_unref(item); // The list store now owns a reference
        }

        delete ud;
        return G_SOURCE_REMOVE;
    }, data, NULL);
}

// Function to remove a cascade from the UI list
void remove_cascade_ui(GListStore *store, const std::string& id) {
    
    std::string *id_ptr = new std::string(id);
    
    g_idle_add_full(G_PRIORITY_DEFAULT, [](gpointer d) -> gboolean {
        std::string *id_str = static_cast<std::string*>(d);
        
        // FIX 2: Use get_app_data(NULL) for thread-safe access to AppData
        AppData *app_data = get_app_data(NULL);
        if (!app_data || !app_data->cascade_list_store) {
            delete id_str;
            return G_SOURCE_REMOVE;
        }

        GListStore *store = app_data->cascade_list_store;
        
        guint n_items = g_list_model_get_n_items(G_LIST_MODEL(store));
        for (guint i = 0; i < n_items; ++i) {
            CascadeItem *item = CASCADE_ITEM(g_list_model_get_item(G_LIST_MODEL(store), i));
            if (item && item->id && *id_str == item->id) {
                g_list_store_remove(store, i);
                g_object_unref(item); // Unref the item we retrieved
                break;
            }
            g_object_unref(item);
        }
        
        delete id_str;
        return G_SOURCE_REMOVE;
    }, id_ptr, NULL);
}

// -------------------- Helpers (unchanged, but moved to the top for clarity) --------------------
// ... (sha256, base64_encode, base64_decode, loadCascade, connectToPeer, sendJson, recvJson functions are assumed to be correct) ...

std::string sha256(const std::vector<char>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.data(), data.size(), hash);
    std::ostringstream out;
    out << "sha256:";
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++)
        out << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return out.str();
}

std::string base64_encode(const std::vector<char>& data) {
    gchar *encoded_data = g_base64_encode((const guchar*)data.data(), data.size());
    std::string result(encoded_data);
    g_free(encoded_data);
    return result;
}

std::vector<char> base64_decode(const std::string& s) {
    gsize output_length;
    guchar *decoded_data = g_base64_decode(s.c_str(), &output_length);
    std::vector<char> out(decoded_data, decoded_data + output_length);
    g_free(decoded_data);
    return out;
}

CascadeMeta loadCascade(const std::string &path) {
    std::ifstream f(path); json j; f >> j;
    CascadeMeta meta;
    meta.fileName = j["file_name"];
    meta.fileSize = j["file_size"];
    meta.pieceSize = j["piece_size"];
    for (auto &p : j["pieces"]) meta.pieces.push_back(p);
    for (auto &peer : j["peers"]) meta.peers.push_back({peer["ip"], (uint16_t)peer["port"]});
    meta.cascadePath = path; // Store the source path
    return meta;
}

int connectToPeer(const Peer &peer) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock<0) return -1;
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(peer.port);
    inet_pton(AF_INET, peer.ip.c_str(), &addr.sin_addr); 
    if(connect(sock,(sockaddr*)&addr,sizeof(addr))<0){close(sock); return -1;}
    return sock;
}

bool sendJson(int sock,const json &j){
    std::string s=j.dump()+"\n";
    return send(sock,s.c_str(),s.size(),0)==(ssize_t)s.size();
}

bool recvJson(int sock,json &j){
    std::string buf; char c;
    while(recv(sock,&c,1,0)==1){if(c=='\n') break; buf+=c;}
    try{j=json::parse(buf);}catch(...){return false;} return true;
}


// -------------------- Auto-Seeder (Updated to use CascadeState ID) --------------------
class CascadeSeeder {
public:
    // Added cascadeId to track the cascade state
    CascadeSeeder(const std::string& cascadeId, const CascadeMeta &m, const std::vector<char> &data, uint16_t port=6881)
        : cascadeId(cascadeId), meta(m), fileData(data), listenPort(port) {}

    void start() { 
        std::thread([this](){serve();}).detach(); 
        std::cout << "Seeding file '" << meta.fileName << "' on port " << listenPort << "\n";
    }

    void stop() {
        if (serverSock != -1) {
            std::cout << "Stopping seeder for '" << meta.fileName << "'...\n";
            stop_flag = true;
            shutdown(serverSock, SHUT_RDWR);
            close(serverSock);
            serverSock = -1;
        }
    }

private:
    std::string cascadeId; // New: Unique ID to find its state
    CascadeMeta meta;
    std::vector<char> fileData;
    uint16_t listenPort;
    std::atomic<bool> stop_flag = false;
    int serverSock = -1;
    std::atomic<int> currentSeeds = 0; // For UI display

    void serve() {
        // ... (Original serve function) ...
        serverSock = socket(AF_INET,SOCK_STREAM,0); 
        if(serverSock < 0) return;
        
        int opt = 1; 
        setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); 
        sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=INADDR_ANY; addr.sin_port=htons(listenPort);
        
        if(bind(serverSock,(sockaddr*)&addr,sizeof(addr)) < 0){close(serverSock); serverSock = -1; return;}
        if(listen(serverSock,10) < 0){close(serverSock); serverSock = -1; return;}
        
        // Initial UI update for seeding status
        AppData *app_data = get_app_data(NULL); // FIX 2
        if (app_data)
            update_cascade_ui(app_data->cascade_list_store, cascadeId, meta.fileName, "Seeding", 1.0, 0);

        while(!stop_flag){
            int clientSock = accept(serverSock, nullptr, nullptr);

            if(stop_flag) break; 

            if(clientSock < 0) continue;
            
            // Increment and update UI
            currentSeeds++;
            if (app_data)
                update_cascade_ui(app_data->cascade_list_store, cascadeId, meta.fileName, "Seeding", 1.0, currentSeeds);

            std::thread([this,clientSock](){handleClient(clientSock);}).detach();
        }
        
        if (serverSock != -1) {
            close(serverSock);
            serverSock = -1;
        }

        // Final UI update upon stop
        if (app_data)
            remove_cascade_ui(app_data->cascade_list_store, cascadeId);
        std::cout << "Seeder thread for '" << meta.fileName << "' exited.\n";
    }

    void handleClient(int sock) {
        // ... (Original handleClient function) ...
        if (stop_flag) { close(sock); return; }

        json j;
        if(!recvJson(sock,j) || j["type"]!="handshake" || j["file"]!=meta.fileName){close(sock); 
            // Decrement and update UI on premature close
            currentSeeds--;
            AppData *app_data = get_app_data(NULL); // FIX 2
            if (app_data)
                update_cascade_ui(app_data->cascade_list_store, cascadeId, meta.fileName, "Seeding", 1.0, currentSeeds);
            return;}
        if(!sendJson(sock,{{"type","handshake_ack"}})){close(sock); 
            // Decrement and update UI
            currentSeeds--;
            AppData *app_data = get_app_data(NULL); // FIX 2
            if (app_data)
                update_cascade_ui(app_data->cascade_list_store, cascadeId, meta.fileName, "Seeding", 1.0, currentSeeds);
            return;}
        
        while(recvJson(sock,j)){
            if (stop_flag) break; 
            if(j["type"]=="request"){
                size_t idx=j["index"];
                size_t offset=idx*meta.pieceSize;
                size_t len=std::min(meta.pieceSize, meta.fileSize-offset);
                std::vector<char> chunk(fileData.begin()+offset,fileData.begin()+offset+len);
                sendJson(sock,{{"type","piece"},{"index",idx},{"data",base64_encode(chunk)}});
            }
        }
        
        close(sock);
        // Decrement and update UI on client close
        currentSeeds--;
        AppData *app_data = get_app_data(NULL); // FIX 2
        if (app_data)
            update_cascade_ui(app_data->cascade_list_store, cascadeId, meta.fileName, "Seeding", 1.0, currentSeeds);
    }
};

// -------------------- Multi-Peer Downloader (Updated for UI feedback) --------------------
class MultiPeerDownloader {
public:
    // New constructor to take cascadeId and AppData
    MultiPeerDownloader(const std::string& cascadeId, CascadeMeta &m, AppData *app_data, size_t maxThreads=4)
        : cascadeId(cascadeId), meta(m), app_data(app_data), maxThreads(maxThreads), finishedPieces(0)
    {
        fileData.resize(meta.fileSize);
        for(size_t i=0;i<meta.pieces.size();i++) tasks.push(i);
        
        // Initial UI update
        update_cascade_ui(app_data->cascade_list_store, cascadeId, meta.fileName, "Downloading", 0.0);
    }

    void start() {
        // ... (Original start function) ...
        std::vector<std::thread> threads;
        for(size_t i=0;i<maxThreads;i++)
            threads.emplace_back(&MultiPeerDownloader::worker,this);
        for(auto &t:threads) t.join();
    }

    void saveFile() {
        // ... (Original saveFile function) ...
        gchar *full_path_gchar = g_build_path(G_DIR_SEPARATOR_S, app_data->download_dir.c_str(), meta.fileName.c_str(), NULL);
        std::string full_path(full_path_gchar);
        g_free(full_path_gchar);

        std::ofstream out(full_path,std::ios::binary);
        if (!out) {
            std::cerr << "Error: Could not open file for writing at " << full_path << std::endl;
            throw std::runtime_error("Could not open file for saving in downloads folder: " + full_path);
        }
        out.write(fileData.data(),fileData.size());
        out.close();

        // Update state with final path
        std::lock_guard<std::mutex> lock(g_state_mutex);
        if (g_active_cascades.count(cascadeId)) {
            g_active_cascades[cascadeId].downloadPath = full_path;
        }
    }

    const std::vector<char>& getFileData() const { return fileData; }

private:
    std::string cascadeId; // New: Unique ID
    CascadeMeta &meta;
    AppData *app_data; // New: Access to the list store
    size_t maxThreads;
    std::vector<char> fileData;
    std::mutex queueMutex, fileMutex;
    std::queue<size_t> tasks;
    std::atomic<size_t> finishedPieces;

    void worker() {
        // ... (Original worker function) ...
        while(true){
            size_t index;
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                if(tasks.empty()) break;
                index=tasks.front(); tasks.pop();
            }

            bool done=false;
            // FIX: Add a simple retry mechanism or peer rotation.
            // For now, iterate through all peers and stop on success.
            for(auto &peer:meta.peers){
                if(downloadPiece(peer,index)) {done=true; break;}
            }

            if(!done){ 
                 std::lock_guard<std::mutex> lock(queueMutex); tasks.push(index);
                 // No UI update on failure/requeue unless we track failed attempts
            }
            if (done) updateProgress(); 
        }
    }

    bool downloadPiece(Peer &peer, size_t index) {
        // ... (Original downloadPiece function - unchanged except for removal of updateProgress) ...
        int sock=connectToPeer(peer); 
        if(sock<0) {
            std::cerr << "Download Error: Failed to connect to peer " << peer.ip << ":" << peer.port << std::endl;
            return false;
        }
        json handshake={{"type","handshake"},{"file",meta.fileName}};
        if(!sendJson(sock,handshake)){close(sock); return false;}
        json resp; if(!recvJson(sock,resp)||resp["type"]!="handshake_ack"){close(sock); return false;}
        json req={{"type","request"},{"index",index}};
        if(!sendJson(sock,req)){close(sock); return false;}
        json pieceResp; 
        
        if(!recvJson(sock,pieceResp)){
            close(sock);
            return false;
        }

        if(pieceResp["type"]!="piece"||pieceResp["index"]!=index){close(sock); return false;}
        
        std::vector<char> chunk;
        try {
            if (pieceResp.contains("data") && pieceResp["data"].is_string()) {
                chunk = base64_decode(pieceResp["data"]);
            } else {
                close(sock);
                std::cerr << "Download Error: Invalid piece data format." << std::endl;
                return false;
            }
        } catch (const std::exception& e) {
            close(sock);
            std::cerr << "Download Error: Base64 decode failed: " << e.what() << std::endl;
            return false;
        }
        
        if(sha256(chunk)!=meta.pieces[index]){
            close(sock); 
            std::cerr << "Download Error: Piece hash mismatch for index " << index << std::endl;
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(fileMutex);
            size_t offset=index*meta.pieceSize;
            size_t len=std::min(chunk.size(), meta.fileSize-offset);
            
            if (offset + len > fileData.size()) {
                std::cerr << "Download Error: Piece offset and length exceed file size." << std::endl;
                close(sock); 
                return false;
            }

            std::copy(chunk.begin(), chunk.begin()+len, fileData.begin()+offset);
        }
        close(sock); 
        finishedPieces++; 
        return true;
    }

    void updateProgress() {
        double current_frac = (double)finishedPieces / meta.pieces.size();
        
        // Update C++ side state
        std::lock_guard<std::mutex> lock(g_state_mutex);
        if (g_active_cascades.count(cascadeId)) {
            g_active_cascades[cascadeId].progressFraction = current_frac;
            std::string status = "Downloading " + std::to_string(static_cast<int>(std::round(current_frac * 100))) + "%";
            g_active_cascades[cascadeId].status = status;
            
            // Trigger UI update
            update_cascade_ui(app_data->cascade_list_store, 
                              cascadeId, 
                              meta.fileName, 
                              status, 
                              current_frac);
        }
    }
};

// -------------------- Cascade Creator (Updated for List View) --------------------
class CascadeCreator {
public:
    // ... (Original CascadeCreator functions - unchanged) ...
    CascadeCreator(const std::string &filename) : filename(filename) {}

    std::pair<CascadeMeta, std::vector<char>> create(uint16_t listenPort = 6881, size_t pieceSize = 512 * 1024) {
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        if (!file) throw std::runtime_error("Could not open file: " + filename);

        size_t totalSize = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<char> fileData(totalSize);
        if (!file.read(fileData.data(), totalSize)) throw std::runtime_error("Could not read full file: " + filename);

        std::vector<std::string> pieces;
        for (size_t offset = 0; offset < totalSize; offset += pieceSize) {
            size_t len = std::min(pieceSize, totalSize - offset);
            std::vector<char> chunk(fileData.begin() + offset, fileData.begin() + offset + len);
            pieces.push_back(sha256(chunk));
        }

        CascadeMeta meta;
        meta.fileName = filename.substr(filename.find_last_of('/') + 1); 
        meta.fileSize = totalSize;
        meta.pieceSize = pieceSize;
        meta.pieces = pieces;
                
        meta.peers.push_back({"127.0.0.1", listenPort}); 
        meta.cascadePath = filename + ".cascade"; // Set source path

        json cascade = {
            {"cascade_version", 1},
            {"file_name", meta.fileName},
            {"file_size", meta.fileSize},
            {"piece_size", meta.pieceSize},
            {"pieces", meta.pieces},
            {"peers", json::array()}
        };
        for (const auto& peer : meta.peers) {
            cascade["peers"].push_back({{"ip", peer.ip}, {"port", peer.port}});
        }

        std::ofstream out(meta.cascadePath);
        if (!out) throw std::runtime_error("Could not create .cascade file: " + meta.cascadePath);
        out << cascade.dump(2);

        return {meta, fileData};
    }

private:
    std::string filename;
};


// -------------------- Core Cascade Management --------------------

// Simplified check using map keys (IDs)
bool is_already_managed(const std::string& id) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    return g_active_cascades.count(id);
}

// Function to stop all seeders on exit
void cleanup_and_quit(GtkApplication *app) {
    std::cout << "Application closing. Initiating graceful shutdown of seeders and stopping downloaders...\n";
    
    std::lock_guard<std::mutex> lock(g_state_mutex);

    for (auto& pair : g_active_cascades) {
        // Stop Seeder if active
        if (pair.second.isSeeding && pair.second.seeder) {
            pair.second.seeder->stop(); 
        }
        // Detach or join downloader thread (if still running, though it should finish fast)
        // For simplicity, we assume the downloader thread will see the stop flag and exit, 
        // but in a real app, a proper cancellation mechanism would be needed.
    }
    
    // Clear the map
    g_active_cascades.clear();

    std::cout << "All cascades signaled to stop. Quitting application.\n";
    g_application_quit(G_APPLICATION(app));
}

// -------------------- C GTK Callbacks - Downloader/Creator Threads --------------------

// Function that runs the download process
void download_thread_func(gpointer data) {
    CascadeMeta *meta_ptr = static_cast<CascadeMeta*>(data);
    CascadeMeta meta = *meta_ptr;
    delete meta_ptr; // Free the dynamically allocated meta
    
    std::string cascadeId = meta.fileName + ":download"; // Use a simple ID for now
    AppData *app_data = get_app_data(NULL); // FIX 2
    if (!app_data) { return; } // Should not happen

    // Get the C++ state reference
    CascadeState *state;
    {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        if (!g_active_cascades.count(cascadeId)) {
            std::cerr << "FATAL: Cascade state not found after starting download thread." << std::endl;
            return;
        }
        state = &g_active_cascades[cascadeId];
        state->status = "Downloading 0%";
    }
        
    try {
        if (meta.pieces.empty() || meta.fileSize == 0) throw std::runtime_error("Cascade file is empty or invalid.");
        if (meta.peers.empty()) throw std::runtime_error("No peers listed in cascade file.");
        
        MultiPeerDownloader downloader(cascadeId, meta, app_data, 4);
        downloader.start();
        downloader.saveFile();

        std::vector<char> downloaded_data = downloader.getFileData();
        
        // --- Start Seeding ---
        std::shared_ptr<CascadeSeeder> seeder = std::make_shared<CascadeSeeder>(cascadeId, meta, downloaded_data, 6881);
        seeder->start();

        {
            std::lock_guard<std::mutex> lock(g_state_mutex);
            state->isSeeding = true;
            state->seeder = seeder;
            state->progressFraction = 1.0;
            state->status = "Complete (Seeding)";
            // The seeder itself updates the UI for seeding count
        }
        
        // Final UI update
        update_cascade_ui(app_data->cascade_list_store, cascadeId, meta.fileName, "Complete (Seeding)", 1.0);

    } catch (const std::exception &e) {
        std::string error_msg = "Download Error: " + std::string(e.what());
        std::cerr << error_msg << std::endl;
        
        // Update C++ state and UI to reflect error
        {
            std::lock_guard<std::mutex> lock(g_state_mutex);
            state->status = "Error: " + std::string(e.what());
            state->progressFraction = 0.0;
        }
        update_cascade_ui(app_data->cascade_list_store, cascadeId, meta.fileName, state->status, 0.0);
        
        // Optional: Pop-up alert (but let the list view be the primary error indicator)

    }
    
    // Clean up the unique_ptr for the thread itself on completion
    // The thread manager handles this; we just ensure the cascade object remains.
}

// Function that runs the creation and seeding process
void create_thread_func(gpointer data) {
    std::string *filePath_ptr = static_cast<std::string*>(data);
    std::string filePath = *filePath_ptr;
    delete filePath_ptr;
    
    AppData *app_data = get_app_data(NULL); // FIX 2
    if (!app_data) { return; } // Should not happen
    
    std::string fileName = filePath.substr(filePath.find_last_of('/') + 1);
    std::string cascadeId = fileName + ":seed";

    try {
        CascadeCreator creator(filePath);
        
        // This is a blocking call that does the file I/O
        auto [meta, fileData] = creator.create(); 

        // --- Start Seeding ---
        std::shared_ptr<CascadeSeeder> seeder = std::make_shared<CascadeSeeder>(cascadeId, meta, fileData, 6881);
        seeder->start();

        // Create and register state
        {
            std::lock_guard<std::mutex> lock(g_state_mutex);
            if (g_active_cascades.count(cascadeId)) {
                // Should not happen if check is done before thread start
                g_active_cascades[cascadeId].seeder->stop(); // Stop old one just in case
            }
            // FIX 3: Creation now uses the custom move constructor/assignment
            g_active_cascades[cascadeId] = CascadeState{
                cascadeId, meta.fileName, "Seeding", 1.0, 0, true, seeder, nullptr, ""
            };
        }
        
        // Initial UI update. The seeder handles subsequent updates.
        update_cascade_ui(app_data->cascade_list_store, cascadeId, meta.fileName, "Seeding", 1.0, 0);

        // Optional: Pop-up confirmation that the .cascade file was created

    } catch (const std::exception &e) {
        std::string error_msg = "Creation Error: " + std::string(e.what());
        std::cerr << error_msg << std::endl;
        
        // Update UI to reflect error (if the item was added at all)
        update_cascade_ui(app_data->cascade_list_store, cascadeId, fileName, "Creation Error", 0.0);
        
        // Clean up C++ state if an error occurred during creation
        std::lock_guard<std::mutex> lock(g_state_mutex);
        g_active_cascades.erase(cascadeId);
    }
}

// -------------------- GTK Callbacks - UI Interactions --------------------

void on_add_cascade_dialog_response(GObject *source_object, GAsyncResult *res, gpointer user_data) {
    AppData *app_data = static_cast<AppData*>(user_data);
    GtkFileDialog *dialog = GTK_FILE_DIALOG(source_object);
    GError *error = NULL;
    GFile *file = gtk_file_dialog_open_finish(dialog, res, &error); 

    if (error) { g_warning("File dialog error: %s", error->message); g_error_free(error); return; }

    if (file) {
        gchar *path = g_file_get_path(file);
        std::string cascade_path(path);
        g_free(path);
        g_object_unref(file);

        try {
            CascadeMeta meta = loadCascade(cascade_path);
            std::string cascadeId = meta.fileName + ":download";
            
            if (is_already_managed(cascadeId)) {
                g_warning("Cascade file is already being managed: %s", meta.fileName.c_str());
                // FIX 5: Remove extra argument from gtk_alert_dialog_new if no format string is used
                GtkAlertDialog *alert_dialog = gtk_alert_dialog_new("File is already active.", NULL);
                const gchar *const buttons[] = {"OK", NULL};
                gtk_alert_dialog_set_buttons(alert_dialog, buttons);
                gtk_alert_dialog_show(alert_dialog, GTK_WINDOW(gtk_widget_get_root(app_data->list_view)));
                g_object_unref(alert_dialog);
                return;
            }

            // Create C++ state entry before starting thread
            {
                std::lock_guard<std::mutex> lock(g_state_mutex);
                // FIX 3: Creation now uses the custom move constructor/assignment
                g_active_cascades[cascadeId] = CascadeState{
                    cascadeId, meta.fileName, "Initializing", 0.0, 0, false, nullptr, nullptr, ""
                };
            }

            // Must allocate meta on heap as it's passed across thread
            CascadeMeta *meta_copy = new CascadeMeta(meta);
            g_thread_new(cascadeId.c_str(), (GThreadFunc)download_thread_func, meta_copy);

        } catch (const std::exception& e) {
             // FIX 5: Ensure correct use of format strings
             GtkAlertDialog *alert_dialog = gtk_alert_dialog_new("Failed to load .cascade file: %s", e.what(), NULL);
             const gchar *const buttons[] = {"OK", NULL};
             gtk_alert_dialog_set_buttons(alert_dialog, buttons);
             gtk_alert_dialog_show(alert_dialog, GTK_WINDOW(gtk_widget_get_root(app_data->list_view)));
             g_object_unref(alert_dialog);
        }
    }
}

void on_add_cascade(GtkButton *button, gpointer user_data) {
    GtkWindow *root_window = GTK_WINDOW(gtk_widget_get_root(GTK_WIDGET(button)));
    GtkFileFilter *filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "Cascade files");
    gtk_file_filter_add_pattern(filter, "*.cascade");
    GtkFileDialog *dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Add .cascade for Download");
    GListStore *filters = g_list_store_new(GTK_TYPE_FILE_FILTER);
    g_list_store_append(filters, filter);
    gtk_file_dialog_set_filters(dialog, G_LIST_MODEL(filters));
    g_object_unref(filter);
    g_object_unref(filters);
    gtk_file_dialog_open(dialog, root_window, NULL, (GAsyncReadyCallback)on_add_cascade_dialog_response, user_data);
}

void on_create_cascade_dialog_response(GObject *source_object, GAsyncResult *res, gpointer user_data) {
    AppData *app_data = static_cast<AppData*>(user_data);
    GtkFileDialog *dialog = GTK_FILE_DIALOG(source_object);
    GError *error = NULL;
    GFile *file = gtk_file_dialog_open_finish(dialog, res, &error); 

    if (error) { g_warning("File dialog error: %s", error->message); g_error_free(error); return; }

    if (file) {
        gchar *path = g_file_get_path(file);
        std::string file_to_cascade_path(path);
        g_free(path);
        g_object_unref(file);
        
        std::string fileName = file_to_cascade_path.substr(file_to_cascade_path.find_last_of('/') + 1);
        std::string cascadeId = fileName + ":seed";

        if (is_already_managed(cascadeId)) {
            g_warning("File is already being seeded: %s", fileName.c_str());
            // FIX 5: Remove extra argument from gtk_alert_dialog_new if no format string is used
            GtkAlertDialog *alert_dialog = gtk_alert_dialog_new("File is already active.", NULL);
            const gchar *const buttons[] = {"OK", NULL};
            gtk_alert_dialog_set_buttons(alert_dialog, buttons);
            gtk_alert_dialog_show(alert_dialog, GTK_WINDOW(gtk_widget_get_root(app_data->list_view)));
            g_object_unref(alert_dialog);
            return;
        }

        // Must allocate path on heap as it's passed across thread
        std::string *path_copy = new std::string(file_to_cascade_path);
        g_thread_new(cascadeId.c_str(), (GThreadFunc)create_thread_func, path_copy);
    }
}

void on_create_cascade(GtkButton *button, gpointer user_data) {
    GtkWindow *root_window = GTK_WINDOW(gtk_widget_get_root(GTK_WIDGET(button)));
    GtkFileDialog *dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Select File to Create & Seed");
    gtk_file_dialog_open(dialog, root_window, NULL, (GAsyncReadyCallback)on_create_cascade_dialog_response, user_data);
}

// -------------------- C GTK Application Setup --------------------

// New: Creates the factory for a column in the list view
GtkListItemFactory* create_progress_factory() {
    GtkListItemFactory *factory = gtk_signal_list_item_factory_new();

    // 1. Setup handler (item is the second argument in the C signal, but we use g_signal_connect)
    g_signal_connect(factory, "setup", G_CALLBACK(+[](GtkListItemFactory *factory, GtkListItem *item, gpointer user_data) {
        GtkWidget *progressbar = gtk_progress_bar_new();
        // The first argument to gtk_list_item_set_child must be GTK_LIST_ITEM(item)
        gtk_list_item_set_child(item, progressbar);
    }), NULL); // user_data is NULL

    // 2. Bind handler
    g_signal_connect(factory, "bind", G_CALLBACK(+[](GtkListItemFactory *factory, GtkListItem *item, gpointer user_data) {
        GtkWidget *progressbar = gtk_list_item_get_child(item);
        CascadeItem *cascade_item = CASCADE_ITEM(gtk_list_item_get_item(item));

        // Format the progress text
        std::string text;
        if (cascade_item->progressFraction < 1.0) {
            text = std::to_string(static_cast<int>(std::round(cascade_item->progressFraction * 100))) + "%";
        } else if (cascade_item->seeds > 0) {
            text = "Seeding (" + std::to_string(cascade_item->seeds) + ")";
        } else {
            text = "100% Complete";
        }

        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(progressbar), cascade_item->progressFraction);
        gtk_progress_bar_set_text(GTK_PROGRESS_BAR(progressbar), text.c_str());

    }), NULL);

    return factory;
}

// New: Creates a simple text factory for other columns
GtkListItemFactory* create_text_factory(const gchar *property_name) {
    GtkListItemFactory *factory = gtk_signal_list_item_factory_new();

    // 1. Setup handler
    g_signal_connect(factory, "setup", G_CALLBACK(+[](GtkListItemFactory *factory, GtkListItem *item, gpointer user_data) {
        GtkWidget *label = gtk_label_new("");
        gtk_label_set_xalign(GTK_LABEL(label), 0.0);
        gtk_list_item_set_child(item, label);
    }), NULL);

    // 2. Bind handler (Note: We pass property_name via the user_data slot)
    // The C signature is (GtkListItemFactory* factory, GtkListItem* item, gpointer user_data)
    g_signal_connect(factory, "bind", G_CALLBACK(+[](GtkListItemFactory *factory, GtkListItem *item, gpointer user_data) {
        const gchar *prop = (const gchar*)user_data; // Retrieve the property name
        GtkWidget *label = gtk_list_item_get_child(item);
        CascadeItem *cascade_item = CASCADE_ITEM(gtk_list_item_get_item(item));
        
        GValue value = G_VALUE_INIT;
        // Use G_TYPE_STRING for all text properties
        g_value_init(&value, G_TYPE_STRING);
        g_object_get_property(G_OBJECT(cascade_item), prop, &value);
        
        gtk_label_set_text(GTK_LABEL(label), g_value_get_string(&value));
        g_value_unset(&value);
    }), (gpointer)property_name); // Pass the property name as data

    return factory;
}

// The main GTK activation function
static void activate(GtkApplication *app, gpointer user_data) {
    AppData *app_data = static_cast<AppData*>(user_data);

    // Create the main window
    GtkWidget *window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "Cascade Client - qBittorrent Style");
    gtk_window_set_default_size(GTK_WINDOW(window), 800, 600); 

    // Main layout container: Vertical Box (Toolbar + Main Content)
    GtkWidget *main_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_window_set_child(GTK_WINDOW(window), main_vbox);

    // Connect cleanup handler
    g_signal_connect_swapped(window, "close-request", G_CALLBACK(cleanup_and_quit), app);

    // -------------------- Toolbar --------------------
    GtkWidget *header_bar = gtk_header_bar_new();
    gtk_header_bar_set_show_title_buttons(GTK_HEADER_BAR(header_bar), TRUE);
    gtk_header_bar_set_title_widget(GTK_HEADER_BAR(header_bar), gtk_label_new("Cascade Client"));

    GtkWidget *toolbar_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_set_margin_start(toolbar_box, 12);
    gtk_widget_set_margin_end(toolbar_box, 12);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header_bar), toolbar_box);

    // "Add Cascade" button
    GtkWidget *btn_add = gtk_button_new_from_icon_name("list-add-symbolic");
    // FIX 4: Use gtk_widget_set_tooltip_text instead of deprecated gtk_button_set_tooltip_text
    gtk_widget_set_tooltip_text(btn_add, "Add Cascade (.cascade file)");
    g_signal_connect(btn_add, "clicked", G_CALLBACK(on_add_cascade), app_data);
    gtk_box_append(GTK_BOX(toolbar_box), btn_add);

    // "Create Cascade" button
    GtkWidget *btn_create = gtk_button_new_from_icon_name("document-new-symbolic");
    // FIX 4: Use gtk_widget_set_tooltip_text instead of deprecated gtk_button_set_tooltip_text
    gtk_widget_set_tooltip_text(btn_create, "Create New Cascade and Seed");
    g_signal_connect(btn_create, "clicked", G_CALLBACK(on_create_cascade), app_data);
    gtk_box_append(GTK_BOX(toolbar_box), btn_create);

    gtk_box_append(GTK_BOX(main_vbox), header_bar);

    // -------------------- Main Content: Scrollable List View --------------------
    
    // 1. Data Model (GListStore)
    GListStore *store = g_list_store_new(CASCADE_TYPE_ITEM);
    app_data->cascade_list_store = store; // Store in app_data

    // 2. Selection Model
    GtkSingleSelection *selection_model = gtk_single_selection_new(G_LIST_MODEL(store));

    // 3. Columns (GtkColumnView)
    GtkColumnView *column_view = GTK_COLUMN_VIEW(gtk_column_view_new(GTK_SELECTION_MODEL(selection_model)));
    
    // File Name Column
    GtkColumnViewColumn *col_file_name = gtk_column_view_column_new("File Name", create_text_factory("file-name"));
    gtk_column_view_append_column(column_view, col_file_name);
    
    // Status Column
    GtkColumnViewColumn *col_status = gtk_column_view_column_new("Status", create_text_factory("status"));
    gtk_column_view_append_column(column_view, col_status);

    // Progress Column (Custom factory for bar/text)
    GtkColumnViewColumn *col_progress = gtk_column_view_column_new("Progress", create_progress_factory());
    gtk_column_view_append_column(column_view, col_progress);
    gtk_column_view_column_set_resizable(col_progress, TRUE);
    gtk_column_view_column_set_fixed_width(col_progress, 150); // Set a good width for the progress bar

    // Seeds Column
    GtkColumnViewColumn *col_seeds = gtk_column_view_column_new("Seeds", create_text_factory("seeds"));
    gtk_column_view_append_column(column_view, col_seeds);
    gtk_column_view_column_set_fixed_width(col_seeds, 60);

    // 4. Scrollable Container
    GtkWidget *scrolled_window = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled_window), GTK_WIDGET(column_view));
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scrolled_window), 200);

    // Store a pointer to the main view for dialogs
    app_data->list_view = scrolled_window;

    // Add list view to main content
    gtk_box_append(GTK_BOX(main_vbox), scrolled_window);
    
    // -------------------- Footer (Optional: for status bar/details) --------------------
    GtkWidget *footer = gtk_label_new("Welcome to Cascade Client. Add or create a cascade to begin.");
    gtk_widget_set_halign(footer, GTK_ALIGN_START);
    gtk_widget_set_margin_start(footer, 12);
    gtk_widget_set_margin_bottom(footer, 12);
    gtk_box_append(GTK_BOX(main_vbox), footer);


    gtk_window_present(GTK_WINDOW(window));
}

// -------------------- Main --------------------
int main(int argc, char **argv) {
    AppData app_data;

    gchar *current_dir = g_get_current_dir();
    if (current_dir) {
        gchar *download_path_gchar = g_build_path(G_DIR_SEPARATOR_S, current_dir, "downloads", NULL);
        app_data.download_dir = download_path_gchar;
        
        if (g_mkdir_with_parents(download_path_gchar, 0775) != 0) {
            std::cerr << "Warning: Could not create downloads directory: " << app_data.download_dir << std::endl;
        }

        g_free(current_dir);
        g_free(download_path_gchar);
    } else {
        app_data.download_dir = "./downloads";
        g_mkdir_with_parents("downloads", 0775);
    }

    // FIX 2: Use g_object_set_data to associate AppData with the GtkApplication object
    GtkApplication *app = gtk_application_new("com.example.cascadeclient", G_APPLICATION_DEFAULT_FLAGS);
    g_object_set_data(G_OBJECT(app), "app-data", &app_data);
    g_signal_connect(app, "activate", G_CALLBACK(activate), &app_data);
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
        
    return status;
}