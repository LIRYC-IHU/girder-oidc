from girder.plugin import GirderPlugin
from girder import events
from . import rest, tasks


class MultiPartZipPlugin(GirderPlugin):
    DISPLAY_NAME = 'Multi-Part Zip Extractor'
    #CLIENT_SOURCE_PATH = 'web_client'
    description = 'Extract multi-part zip files'

    def load(self, info):
        # 1. Register the new REST resource
        info['apiRoot'].zip_tool = rest.ZipTool()

        # 2. Bind the job schedule event to our local executor
        events.bind('jobs.schedule', 'multipart_zip_handler', runZipJob)


def runZipJob(event):
    """
    Event handler that listens for 'jobs.schedule' events.
    If the job type matches, it runs the task locally.
    """
    job = event.info
    if job.get('type') == 'multipart_zip_extract':
        # Prevent other handlers (like girder-worker/celery) from taking this job
        event.preventDefault()
        tasks.extract_multipart_item_job(job)

