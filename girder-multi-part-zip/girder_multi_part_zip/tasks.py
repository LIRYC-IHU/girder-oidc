import os
import zipfile
import shutil
from girder.models.item import Item
from girder.models.file import File
from girder.models.folder import Folder
from girder.models.upload import Upload
from girder.models.user import User

# Correct namespaced imports
from girder_jobs.models.job import Job
from girder_jobs.constants import JobStatus


# List of files to exclude during extraction
EXCLUDE_FILES = {'.DS_Store', '__MACOSX'}

def extract_multipart_item_job(job):
    Job().updateJob(job, status=JobStatus.RUNNING, log='Starting extraction task...\n')
    
    item_id = job['kwargs'].get('item_id')
    target_id = job['kwargs'].get('target_id')
    delete_after = job['kwargs'].get('delete_after', False)
    work_dir = '/assetstore/tmp_extraction'
    
    # Initialize cleanup variables upfront
    combined_zip_path = None
    extract_path = None

    try:
        if not os.path.exists(work_dir):
            os.makedirs(work_dir)

        # 1. Charger l'item et l'utilisateur créateur
        item = Item().load(item_id, force=True, exc=True)
        # Il nous faut l'objet User complet pour les fonctions de création
        user = User().load(job['userId'], force=True) 

        # Le parent d'un Item est TOUJOURS un Folder dans Girder
        if target_id:
            parent_folder = Folder().load(target_id, force=True, exc=True)
        else:
            parent_folder = Folder().load(item['folderId'], force=True, exc=True)

        # 2. Reconstruit le fichier ZIP complet
        files = sorted(list(Item().childFiles(item)), key=lambda f: f['name'])
        combined_zip_path = os.path.join(work_dir, f"{item_id}.zip")
        
        with open(combined_zip_path, 'wb') as outfile:
            for f_obj in files:
                Job().updateJob(job, log=f"Appending {f_obj['name']}...\n")
                # Utilisation du générateur de download
                for chunk in File().download(f_obj, headers=False)():
                    outfile.write(chunk)
        
        # 3. Extraction and upload
        extract_path = os.path.join(work_dir, f"extracted_{item_id}")
        with zipfile.ZipFile(combined_zip_path, 'r') as z:
            for member in z.infolist():
                if member.is_dir():
                    continue
                if any(part in EXCLUDE_FILES for part in member.filename.split('/')):
                    Job().updateJob(job, log=f"Skipping excluded file: {member.filename}\n")
                    continue
                z.extract(member, extract_path)
                file_physical_path = os.path.join(extract_path, member.filename)
                
                # Gestion de l'arborescence
                relative_path = member.filename
                path_parts = relative_path.split('/')
                filename = path_parts[-1]
                sub_folders = path_parts[:-1]

                current_parent = parent_folder
                for folder_name in sub_folders:
                    # On descend dans l'arborescence en créant les dossiers si besoin
                    current_parent = Folder().createFolder(
                        current_parent, folder_name, parentType='folder',
                        creator=user, reuseExisting=True
                    )

                # 4. Upload vers Girder
                with open(file_physical_path, 'rb') as f:
                    Upload().uploadFromFile(
                        f, size=member.file_size, name=filename,
                        parentType='folder', parent=current_parent,
                        user=user
                    )
                
                Job().updateJob(job, log=f"Extracted and imported: {relative_path}\n")

        Job().updateJob(job, status=JobStatus.SUCCESS, log="Success!\n")
        
        # 5. Nettoyage de l'item original si demandé
        if delete_after:
            Item().remove(item)
            Job().updateJob(job, log="Original item deleted after extraction.\n")
        
    except Exception as e:
        # Capture de l'erreur précise pour le log
        import traceback
        error_msg = f"Error: {str(e)}\n{traceback.format_exc()}"
        Job().updateJob(job, status=JobStatus.ERROR, log=error_msg)
    
    finally:
        # Cleanup temporary files
        if extract_path and os.path.exists(extract_path):
            shutil.rmtree(extract_path)
        if combined_zip_path and os.path.exists(combined_zip_path):
            os.remove(combined_zip_path)

        