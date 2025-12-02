import { getCurrentUser } from '@girder/core/auth';
import UserAccountView from '@girder/core/views/body/UserAccountView';
import View from '@girder/core/views/View';
import { wrap } from '@girder/core/utilities/PluginUtils';
import { restRequest } from '@girder/core/rest';

import template from '../templates/oidcUserAccountView.pug';
import '../stylesheets/oidcUserAccountView.styl';

console.log('SettingsInterceptor.js loading...');

/**
 * Check if current user is an OIDC user by calling the REST API
 */
function isOidcUser(callback) {
    console.log('[SettingsInterceptor] isOidcUser() called');
    const user = getCurrentUser();
    console.log('[SettingsInterceptor] getCurrentUser() returned:', user);
    
    if (!user) {
        console.log('[SettingsInterceptor] No user found, calling callback(false)');
        callback(false);
        return;
    }
    
    console.log('[SettingsInterceptor] Calling REST API endpoint: /api/v1/oidc/is-oidc-user');
    // Call the REST API endpoint to check if user is OIDC
    restRequest({
        method: 'GET',
        url: 'oidc/is-oidc-user',
        error: null
    }).done(function (resp) {
        console.log('[SettingsInterceptor] REST API response:', resp);
        const isOidc = resp.isOidcUser === true;
        console.log('[SettingsInterceptor] isOidcUser result:', isOidc);
        callback(isOidc);
    }).fail(function (error) {
        console.error('[SettingsInterceptor] REST API call failed:', error);
        // If endpoint fails, assume not OIDC
        console.log('[SettingsInterceptor] Assuming not OIDC due to API failure');
        callback(false);
    });
}

/**
 * OIDC User Account View Extension
 */
var OidcUserAccountView = View.extend({
    initialize: function (settings) {
        console.log('[SettingsInterceptor] OidcUserAccountView.initialize() called');
        console.log('[SettingsInterceptor] Settings:', settings);
    },

    render: function () {
        console.log('[SettingsInterceptor] OidcUserAccountView.render() called');
        console.log('[SettingsInterceptor] Rendering OIDC account view template');
        this.$el.html(template());
        console.log('[SettingsInterceptor] OidcUserAccountView rendered successfully');
        return this;
    },
});

/**
 * Wrap the core UserAccountView render method to disable tabs for OIDC users
 */
wrap(UserAccountView, 'render', function (render) {
    console.log('[SettingsInterceptor] UserAccountView.render() intercepted');
    console.log('[SettingsInterceptor] this.user:', this.user);
    const self = this;
    
    // Check if user is OIDC asynchronously
    isOidcUser(function (isOidc) {
        console.log('[SettingsInterceptor] isOidcUser callback executed with result:', isOidc);
        if (isOidc) {
            console.log('[SettingsInterceptor] ✓ Current user IS an OIDC user - rendering OidcUserAccountView');
            const oidcView = new OidcUserAccountView();
            console.log('[SettingsInterceptor] Created OidcUserAccountView instance');
            self.$el.html(oidcView.render().$el);
            console.log('[SettingsInterceptor] OidcUserAccountView rendered to DOM');
        } else {
            console.log('[SettingsInterceptor] ✗ Current user is NOT an OIDC user - original view already rendered');
        }
    });
    
    console.log('[SettingsInterceptor] Calling original UserAccountView.render()');
    // Call the original render method first
    return render.call(this);
});

export default {isOidcUser, OidcUserAccountView};
