import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import List
from fastapi import FastAPI, File, UploadFile, HTTPException, status
from fastapi.responses import HTMLResponse, FileResponse

app = FastAPI(title="Secure File Upload Pro", version="3.0")

# Configuration
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".pdf", ".txt"}
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "application/pdf", "text/plain"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB limit[cite: 1]

# In-memory database records for uploaded metadata & security logs
file_metadata_db = []
security_audit_logs = []

def log_event(event_type: str, details: str, status_label: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    security_audit_logs.insert(0, {
        "timestamp": timestamp,
        "type": event_type,
        "details": details,
        "status": status_label
    })

def get_file_extension(filename: str) -> str:
    return Path(filename).suffix.lower()

# 1. Stunning Interactive Dashboard UI (HTML / Tailwind CSS)
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Secure File Upload Pro | Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    </head>
    <body class="bg-slate-950 text-slate-100 min-h-screen font-sans antialiased selection:bg-indigo-500 selection:text-white">
        <!-- Navbar -->
        <nav class="border-b border-slate-800 bg-slate-900/50 backdrop-blur sticky top-0 z-50 px-6 py-4 flex justify-between items-center">
            <div class="flex items-center space-x-3">
                <div class="bg-indigo-600 p-2.5 rounded-xl shadow-lg shadow-indigo-500/30">
                    <i class="fa-solid fa-shield-halved text-white text-lg"></i>
                </div>
                <div>
                    <h1 class="font-bold text-lg tracking-wide text-white">SecureUpload <span class="text-indigo-400">API</span></h1>
                    <p class="text-xs text-slate-400">Python Web Security Demonstration</p>
                </div>
            </div>
            <div class="flex items-center space-x-2 text-xs bg-slate-800 px-3 py-1.5 rounded-full border border-slate-700">
                <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span class="text-slate-300 font-medium">Protection Active</span>
            </div>
        </nav>

        <!-- Main Grid Container -->
        <main class="max-w-7xl mx-auto p-6 grid grid-cols-1 lg:grid-cols-3 gap-8 mt-4">
            
            <!-- Left Column: Upload Panel & Rules -->
            <div class="lg:col-span-1 space-y-6">
                <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl backdrop-blur">
                    <h2 class="text-lg font-semibold text-white mb-1"><i class="fa-solid fa-cloud-arrow-up text-indigo-400 mr-2"></i>Upload Center</h2>
                    <p class="text-xs text-slate-400 mb-4">Select or drag files to test secure server validation.</p>
                    
                    <form id="uploadForm" class="space-y-4">
                        <div class="border-2 border-dashed border-slate-700 rounded-xl p-6 text-center hover:border-indigo-500 transition group cursor-pointer bg-slate-950/40">
                            <input type="file" id="fileInput" name="files" multiple class="hidden" required>
                            <label for="fileInput" class="cursor-pointer block">
                                <i class="fa-solid fa-file-arrow-up text-3xl text-slate-500 group-hover:text-indigo-400 transition mb-2"></i>
                                <span class="block text-sm font-medium text-slate-300">Browse files to upload</span>
                                <span class="block text-xs text-slate-500 mt-1">Max size: 5MB per file</span>
                            </label>
                        </div>
                        <div id="fileSelectionList" class="text-xs text-indigo-300 space-y-1 font-mono max-h-28 overflow-y-auto"></div>
                        
                        <button type="submit" class="w-full py-3 px-4 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-xl shadow-lg shadow-indigo-600/30 transition duration-200 flex items-center justify-center space-x-2 text-sm">
                            <i class="fa-solid fa-lock"></i>
                            <span>Secure Upload Now</span>
                        </button>
                    </form>
                    <div id="alertMessage" class="mt-4 hidden p-3 rounded-xl text-xs font-medium"></div>
                </div>

                <!-- Security Rules Checklist -->
                <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl">
                    <h3 class="text-sm font-semibold text-slate-200 uppercase tracking-wider mb-3 flex items-center">
                        <i class="fa-solid fa-list-check text-emerald-400 mr-2"></i> Active Security Defenses
                    </h3>
                    <ul class="space-y-2 text-xs text-slate-400">
                        <li class="flex items-center"><i class="fa-solid fa-check text-emerald-400 mr-2"></i> Filename Path Traversal Sanitization</li>
                        <li class="flex items-center"><i class="fa-solid fa-check text-emerald-400 mr-2"></i> Strict Extension & MIME Whitelist</li>
                        <li class="flex items-center"><i class="fa-solid fa-check text-emerald-400 mr-2"></i> Payload Size Cap (5MB max)</li>
                        <li class="flex items-center"><i class="fa-solid fa-check text-emerald-400 mr-2"></i> Isolated Application Storage</li>
                    </ul>
                </div>
            </div>

            <!-- Right Column: Repository & Security Logs -->
            <div class="lg:col-span-2 space-y-6">
                <!-- Stored Files Table -->
                <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl backdrop-blur">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-lg font-semibold text-white flex items-center">
                            <i class="fa-solid fa-server text-indigo-400 mr-2"></i> Uploaded Files Vault
                        </h2>
                        <button onclick="loadFiles()" class="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1.5 rounded-lg transition border border-slate-700">
                            <i class="fa-solid fa-rotate-right mr-1"></i> Refresh
                        </button>
                    </div>
                    <div class="overflow-x-auto rounded-xl border border-slate-800">
                        <table class="w-full text-left text-xs text-slate-300">
                            <thead class="bg-slate-950 uppercase text-slate-400 font-semibold">
                                <tr>
                                    <th class="p-3">Original Name</th>
                                    <th class="p-3">Stored ID Filename</th>
                                    <th class="p-3">Size</th>
                                    <th class="p-3 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody id="filesTableBody" class="divide-y divide-slate-800 bg-slate-900/40">
                                <tr><td colspan="4" class="p-4 text-center text-slate-500">Loading vault contents...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Security Live Audit Feed -->
                <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl backdrop-blur">
                    <h2 class="text-lg font-semibold text-white mb-4 flex items-center">
                        <i class="fa-solid fa-shield-dog text-amber-400 mr-2"></i> Security Audit Trail
                    </h2>
                    <div id="auditLogContainer" class="space-y-2 max-h-48 overflow-y-auto pr-2 font-mono text-xs">
                        <div class="text-slate-500 text-center py-2">No security triggers yet.</div>
                    </div>
                </div>
            </div>
        </main>

        <script>
            const fileInput = document.getElementById('fileInput');
            const fileSelectionList = document.getElementById('fileSelectionList');

            fileInput.onchange = () => {
                fileSelectionList.innerHTML = Array.from(fileInput.files)
                    .map(f => `<div class="truncate">📄 ${f.name} (${(f.size/1024/1024).toFixed(2)} MB)</div>`)
                    .join('');
            };

            document.getElementById('uploadForm').onsubmit = async (e) => {
                e.preventDefault();
                const alertBox = document.getElementById('alertMessage');
                const formData = new FormData();
                for (let file of fileInput.files) {
                    formData.append('files', file);
                }

                alertBox.classList.remove('hidden', 'bg-emerald-950', 'text-emerald-300', 'bg-rose-950', 'text-rose-300');
                alertBox.className = "mt-4 p-3 rounded-xl text-xs font-medium bg-slate-800 text-indigo-300 border border-slate-700";
                alertBox.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i> Processing uploads through security filters...';

                try {
                    const response = await fetch('/upload/', { method: 'POST', body: formData });
                    const result = await response.json();
                    
                    if (response.ok) {
                        alertBox.className = "mt-4 p-3 rounded-xl text-xs font-medium bg-emerald-950/80 text-emerald-300 border border-emerald-800";
                        alertBox.innerHTML = `<i class="fa-solid fa-circle-check mr-2"></i> Success: ${result.message}`;
                        fileInput.value = '';
                        fileSelectionList.innerHTML = '';
                        loadFiles();
                        loadLogs();
                    } else {
                        alertBox.className = "mt-4 p-3 rounded-xl text-xs font-medium bg-rose-950/80 text-rose-300 border border-rose-800";
                        alertBox.innerHTML = `<i class="fa-solid fa-triangle-exclamation mr-2"></i> Blocked: ${result.detail}`;
                        loadLogs();
                    }
                } catch (err) {
                    alertBox.className = "mt-4 p-3 rounded-xl text-xs font-medium bg-rose-950/80 text-rose-300 border border-rose-800";
                    alertBox.innerHTML = '<i class="fa-solid fa-circle-xmark mr-2"></i> Network connection error.';
                }
            };

            async function loadFiles() {
                try {
                    const res = await fetch('/files/');
                    const data = await res.json();
                    const tbody = document.getElementById('filesTableBody');
                    if (data.files.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="4" class="p-4 text-center text-slate-500">Vault is empty.</td></tr>';
                        return;
                    }
                    tbody.innerHTML = data.files.map(f => `
                        <tr class="hover:bg-slate-800/50 transition">
                            <td class="p-3 font-medium text-slate-200 truncate max-w-[150px]">${f.original_filename}</td>
                            <td class="p-3 text-slate-400 font-mono truncate max-w-[180px]">${f.stored_filename}</td>
                            <td class="p-3 text-slate-400">${(f.size_bytes/1024).toFixed(1)} KB</td>
                            <td class="p-3 text-right">
                                <a href="/files/${f.stored_filename}" target="_blank" class="px-2.5 py-1 bg-indigo-600/30 hover:bg-indigo-600 text-indigo-300 hover:text-white rounded-lg transition text-xs border border-indigo-500/30">
                                    <i class="fa-solid fa-download"></i>
                                </a>
                            </td>
                        </tr>
                    `).join('');
                } catch (e) { console.error(e); }
            }

            async function loadLogs() {
                try {
                    const res = await fetch('/logs/');
                    const data = await res.json();
                    const container = document.getElementById('auditLogContainer');
                    if (data.logs.length === 0) {
                        container.innerHTML = '<div class="text-slate-500 text-center py-2">No security triggers yet.</div>';
                        return;
                    }
                    container.innerHTML = data.logs.map(l => `
                        <div class="p-2.5 rounded-lg bg-slate-950/60 border ${l.status === 'SUCCESS' ? 'border-emerald-500/20 text-emerald-400' : 'border-rose-500/20 text-rose-400'} flex justify-between items-center">
                            <div>
                                <span class="text-slate-500 mr-2">[${l.timestamp}]</span>
                                <span class="font-bold text-slate-300">${l.type}:</span> ${l.details}
                            </div>
                            <span class="px-2 py-0.5 rounded text-[10px] ${l.status === 'SUCCESS' ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'}">${l.status}</span>
                        </div>
                    `).join('');
                } catch (e) { console.error(e); }
            }

            // Initial load on page mount
            loadFiles();
            loadLogs();
        </script>
    </body>
    </html>
    """

# 2. Multiple File Secure Upload Endpoint
@app.post("/upload/", status_code=status.HTTP_201_CREATED)
async def upload_files(files: List[UploadFile] = File(...)):
    uploaded_summary = []

    for file in files:
        if not file.filename:
            log_event("VALIDATION", "Rejected file with missing filename parameter.", "BLOCKED")
            raise HTTPException(status_code=400, detail="One or more files lack a valid filename.")

        # Check Extension Whitelist
        file_ext = get_file_extension(file.filename)
        if file_ext not in ALLOWED_EXTENSIONS:
            log_event("SECURITY", f"Attempted upload with blocked extension: '{file_ext}' ({file.filename})", "BLOCKED")
            raise HTTPException(status_code=400, detail=f"Extension '{file_ext}' is not permitted. Allowed: {list(ALLOWED_EXTENSIONS)}")

        # Check MIME Content-Type Whitelist
        if file.content_type not in ALLOWED_MIME_TYPES:
            log_event("SECURITY", f"Attempted upload with unauthorized MIME type: '{file.content_type}'", "BLOCKED")
            raise HTTPException(status_code=400, detail=f"MIME type '{file.content_type}' is forbidden.")

        # Read contents & enforce Size Restrictions
        file_contents = await file.read()
        file_size = len(file_contents)
        
        if file_size > MAX_FILE_SIZE:
            log_event("DOS_PROTECTION", f"Oversized file upload blocked: {file.filename} ({file_size} bytes)", "BLOCKED")
            raise HTTPException(status_code=413, detail=f"File '{file.filename}' exceeds the 5MB size limit[cite: 1].")
        
        if file_size == 0:
            log_event("VALIDATION", f"Empty file upload ignored: {file.filename}", "BLOCKED")
            raise HTTPException(status_code=400, detail=f"File '{file.filename}' is empty.")

        # Prevent Path Traversal by isolating base name & assigning unique ID UUID key[cite: 1]
        safe_name = os.path.basename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{safe_name}"
        destination_path = UPLOAD_DIR / unique_filename

        # Write safely outside web root/source paths[cite: 1]
        try:
            with open(destination_path, "wb") as buffer:
                buffer.write(file_contents)
        except Exception as e:
            log_event("SYSTEM", f"Disk write error for {file.filename}", "ERROR")
            raise HTTPException(status_code=500, detail="Internal error saving file storage.")

        metadata = {
            "id": str(uuid.uuid4()),
            "stored_filename": unique_filename,
            "original_filename": file.filename,
            "size_bytes": file_size,
            "content_type": file.content_type,
            "uploaded_at": datetime.utcnow().isoformat()
        }
        file_metadata_db.append(metadata)
        uploaded_summary.append(metadata)
        log_event("UPLOAD", f"Successfully stored safe file: {file.filename}", "SUCCESS")

    return {"message": "All files successfully passed security validation and uploaded.", "files": uploaded_summary}

# 3. Retrieve Metadata List Endpoint
@app.get("/files/")
async def list_files():
    return {"total_files": len(file_metadata_db), "files": file_metadata_db}

# 4. Security Audit Logs Feed Endpoint
@app.get("/logs/")
async def get_audit_logs():
    return {"logs": security_audit_logs}

# 5. Secure File Download Endpoint
@app.get("/files/{stored_filename}")
async def download_file(stored_filename: str):
    # Safeguard path traversal on lookup
    safe_filename = os.path.basename(stored_filename)
    file_path = UPLOAD_DIR / safe_filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found in storage repository.")
    
    return FileResponse(path=file_path, filename=safe_filename)

if __name__ == "__main__":
    import uvicorn
    # Change "app:app" to "API:app" because your file is named API.py
    uvicorn.run("API:app", host="127.0.0.1", port=8000, reload=True)