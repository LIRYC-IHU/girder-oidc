from girder.constants import AccessType
from girder.api.describe import Description, autoDescribeRoute
from girder.api.rest import Resource
from girder.api import access

from girder.models.item import Item
from girder.models.folder import Folder

from girder_jobs.models.job import Job


class ZipTool(Resource):
    """ REST endpoints for multi-part zip extraction """
    def __init__(self):
        super().__init__()
        self.resourceName = 'zip_tool'
        self.route('POST', ('extract', ':id'), self.triggerExtraction)

    @access.user
    @autoDescribeRoute(
        Description('Concatenate and extract multipart zip files within an item.')
        .modelParam('id', 'The ID of the item containing the zip parts.', model=Item, level=AccessType.READ)
        .param('target_id', 'The ID of the target folder where to extract the contents. (default: same folder as the item)', dataType='string', required=False, default=None)
        .param('delete_after', 'Whether to delete the original item after extraction.',
                    dataType='boolean', required=False, default=False)
        .notes('The item should contain files named sequentially (e.g., .001, .002).')
    )
    def triggerExtraction(self, item, target_id, delete_after):
        """ 
        Launch the extraction of a multi-part zipfile
        """
        user = self.getCurrentUser()

        # Check that the folder exists and that the user has write access
        if target_id:
            target_folder = Folder().load(target_id, user=user, level=AccessType.WRITE, exc=True)
        else:
            target_folder = Folder().load(item['folderId'], user=user, level=AccessType.WRITE, exc=True)
        
        # Using the namespaced Job model singleton
        job = Job().createJob(
            title=f"Extracting multipart zip: {item['name']}",
            type='multipart_zip_extract',
            handler='local_handler',
            user=user,
            public=False,
            kwargs={'item_id': str(item['_id']), 'target_id': str(target_folder['_id']), 'delete_after': delete_after}
        )
        
        Job().scheduleJob(job)
        return job