import $ from 'jquery';
import _ from 'underscore';

import PluginConfigBreadcrumbWidget from '@girder/core/views/widgets/PluginConfigBreadcrumbWidget';
import View from '@girder/core/views/View';
import { getApiRoot, restRequest } from '@girder/core/rest';
import events from '@girder/core/events';

import template from '../templates/configView.pug';
import '../stylesheets/configView.styl';

/**
 * Admin configuration view for OIDC/Keycloak settings.
 */
var ConfigView = View.extend({
    events: {
        'click .g-oidc-save-config': 'saveConfiguration',
        'click .g-oidc-test-connection': 'testConnection'
    },

    initialize: function (settings) {
        console.log('ConfigView.initialize() called with settings:', settings);
        this.render();
    },

    render: function () {
        console.log('ConfigView.render() called');
        console.log('this.$el:', this.$el);
        
        // Render empty template first
        const configData = {
            keycloakUrl: '',
            keycloakPublicUrl: '',
            keycloakRealm: '',
            clientId: '',
            clientSecret: '',
            enable: false,
            autoCreateUsers: false,
            allowRegistration: false,
            ignoreRegistrationPolicy: false
        };
        
        console.log('Rendering template with initial data:', configData);
        this.$el.html(template(configData));
        console.log('Template rendered');
        this.delegateEvents();

        // Add breadcrumb widget
        if (!this.breadcrumb) {
            try {
                console.log('Creating breadcrumb widget');
                this.breadcrumb = new PluginConfigBreadcrumbWidget({
                    pluginName: 'OIDC/Keycloak Login',
                    el: this.$('.g-config-breadcrumb-container'),
                    parentView: this
                }).render();
                console.log('Breadcrumb widget created');
            } catch (e) {
                console.error('Breadcrumb widget error:', e);
            }
        }
        
        // Now fetch and update the configuration asynchronously
        console.log('Fetching OIDC configuration from server');
        restRequest({
            method: 'GET',
            url: 'oidc/configuration'
        }).done((config) => {
            console.log('OIDC Configuration loaded:', config);
            // Update form fields with fetched values
            if (config.keycloakUrl) {
                this.$('[name="keycloakUrl"]').val(config.keycloakUrl);
            }
            if (config.keycloakPublicUrl) {
                this.$('[name="keycloakPublicUrl"]').val(config.keycloakPublicUrl);
            }
            if (config.keycloakRealm) {
                this.$('[name="keycloakRealm"]').val(config.keycloakRealm);
            }
            if (config.clientId) {
                this.$('[name="clientId"]').val(config.clientId);
            }
            if (config.enable) {
                this.$('[name="enable"]').prop('checked', config.enable);
            }
            if (config.autoCreateUsers) {
                this.$('[name="autoCreateUsers"]').prop('checked', config.autoCreateUsers);
            }
            if (config.allowRegistration) {
                this.$('[name="allowRegistration"]').prop('checked', config.allowRegistration);
            }
            if (config.ignoreRegistrationPolicy) {
                this.$('[name="ignoreRegistrationPolicy"]').prop('checked', config.ignoreRegistrationPolicy);
            }
            console.log('Configuration values updated in form');
        }).error((err) => {
            console.error('Failed to load OIDC configuration:', err);
            const errorMsg = err.responseJSON && err.responseJSON.message ? err.responseJSON.message : 'Unknown error';
            this.$el.find('.g-oidc-save-message').html(
                '<div class="alert alert-danger">Failed to load OIDC configuration: ' + errorMsg + '</div>'
            );
        });

        console.log('ConfigView.render() returning');
        return this;
    },

    saveConfiguration(e) {
        e.preventDefault();

        const config = {
            keycloakUrl: this.$el.find('[name="keycloakUrl"]').val().trim(),
            keycloakPublicUrl: this.$el.find('[name="keycloakPublicUrl"]').val().trim(),
            keycloakRealm: this.$el.find('[name="keycloakRealm"]').val().trim(),
            clientId: this.$el.find('[name="clientId"]').val().trim(),
            clientSecret: this.$el.find('[name="clientSecret"]').val().trim(),
            enable: this.$el.find('[name="enable"]').prop('checked'),
            autoCreateUsers: this.$el.find('[name="autoCreateUsers"]').prop('checked'),
            allowRegistration: this.$el.find('[name="allowRegistration"]').prop('checked'),
            ignoreRegistrationPolicy: this.$el.find('[name="ignoreRegistrationPolicy"]').prop('checked')
        };

        restRequest({
            method: 'PUT',
            url: 'oidc/configuration',
            data: config,
            error: null
        }).done(() => {
            events.trigger('g:alert', {
                icon: 'ok',
                text: 'OIDC configuration saved successfully.',
                type: 'success',
                timeout: 3000
            });
        }).fail((resp) => {
            const errorMsg = resp.responseJSON && resp.responseJSON.message ? resp.responseJSON.message : 'Unknown error';
            events.trigger('g:alert', {
                icon: 'cancel',
                text: 'Failed to save OIDC configuration: ' + errorMsg,
                type: 'danger',
                timeout: 5000
            });
        });
    },

    testConnection(e) {
        e.preventDefault();

        // Test connection to Keycloak
        restRequest({
            method: 'GET',
            url: 'oidc/configuration',
            error: null
        }).done(() => {
            events.trigger('g:alert', {
                icon: 'ok',
                text: 'Connection to Keycloak successful!',
                type: 'success',
                timeout: 3000
            });
        }).fail((resp) => {
            const errorMsg = resp.responseJSON && resp.responseJSON.message ? resp.responseJSON.message : 'Unknown error';
            events.trigger('g:alert', {
                icon: 'cancel',
                text: 'Connection to Keycloak failed: ' + errorMsg,
                type: 'danger',
                timeout: 5000
            });
        });
    }
});

export default ConfigView;
