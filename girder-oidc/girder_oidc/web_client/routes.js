/* eslint-disable import/first */

import events from '@girder/core/events';
import router from '@girder/core/router';
import { exposePluginConfig } from '@girder/core/utilities/PluginUtils';

exposePluginConfig('oidc', 'plugins/oidc/config');

import ConfigView from './views/ConfigView';
router.route('plugins/oidc/config', 'oidcConfig', function () {
    console.log('Route handler for plugins/oidc/config triggered');
    events.trigger('g:navigateTo', ConfigView);
});