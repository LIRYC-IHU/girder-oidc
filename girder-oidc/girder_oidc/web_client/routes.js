import ConfigView from './views/ConfigView';

const events = girder.events;
const router = girder.router;
const { exposePluginConfig } = girder.utilities.PluginUtils;

exposePluginConfig('oidc', 'plugins/oidc/config');

router.route('plugins/oidc/config', 'oidcConfig', function () {
    events.trigger('g:navigateTo', ConfigView);
});
