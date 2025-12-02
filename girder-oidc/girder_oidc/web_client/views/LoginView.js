import CoreLoginView from '@girder/core/views/layout/LoginView';
import { wrap } from '@girder/core/utilities/PluginUtils';
import View from '@girder/core/views/View';
import { restRequest } from '@girder/core/rest';

import template from '../templates/oauthLoginView.pug';
import '../stylesheets/oauthLoginView.styl';

/**
 * OIDC login button view that gets inserted into the core login modal.
 */
var OidcLoginView = View.extend({
    events: {
        'click .g-oidc-login': 'oidcLogin'
    },

    initialize: function (settings) {
        console.log('OidcLoginView.initialize() called with settings:', settings);
        this.enablePasswordLogin = settings.enablePasswordLogin;
        //this.render();
    },

    render: function () {
        console.log('OidcLoginView.render() called');
        this.$el.append(template({
            apiRoot: '/api/v1'
        }));
        console.log('OidcLoginView rendered');
        return this;
    },

    oidcLogin: function () {
        console.log('oidcLogin() clicked');
        const redirect = window.location.pathname + window.location.search;
        console.log('Redirect URL:', redirect);
        
        restRequest({
            method: 'GET',
            url: 'oidc/login',
            data: { redirect },
            error: null
        }).done((resp) => {
            console.log('OIDC login URL received:', resp.url);
            window.location.href = resp.url;
        }).fail((err) => {
            console.error('Failed to initiate OIDC login:', err);
        });
    }
});

/**
 * Wrap the core LoginView render method to insert OIDC login option.
 */
wrap(CoreLoginView, 'render', function (render) {
    console.log('Wrapping CoreLoginView.render()');
    render.call(this);
    console.log('Creating OidcLoginView in modal-body - prepending before default login');
    
    // Create the OIDC login view
    const oidcView = new OidcLoginView({
        el: $('<div>'),
        parentView: this,
        enablePasswordLogin: this.enablePasswordLogin
    }).render();
    
    // Prepend it to the modal body (before the default login form)
    this.$('.modal-body').prepend(oidcView.$el);
    return this;
});

export default OidcLoginView;
