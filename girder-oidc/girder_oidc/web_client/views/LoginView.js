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

    oidcLogin: function (e) {
        // Prevent the default form submission behavior
        e.preventDefault();
        e.stopPropagation();

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
    render.call(this);

    // 1. On identifie les éléments du login classique à cacher
    // On cible les form-groups, les messages du bas, et le bouton de soumission dans le footer
    const $classicElements = this.$('.form-group, .g-bottom-message, #g-login-button');

    // 2. On insère notre interface de contrôle avant les éléments classiques
    this.$('.modal-body').append(`
        <div class="g-alternative-login-separator" style="margin: 20px 0; text-align: center; border-bottom: 1px solid #eee; line-height: 0.1em;">
            <span style="background:#fff; padding:0 10px; color: #999; font-size: 12px;">OU</span>
        </div>
        <div style="text-align: center; margin-bottom: 15px;">
            <a class="g-toggle-password-login" style="cursor: pointer; font-size: 13px;">
                <i class="icon-down-dir"></i> Utiliser un compte local Girder
            </a>
        </div>
    `);

    // 3. On cache les éléments classiques par défaut
    $classicElements.hide();

    // 4. Logique de bascule (Toggle)
    this.$('.g-toggle-password-login').on('click', (e) => {
        e.preventDefault();
        $classicElements.slideToggle();
        const $icon = this.$('.g-toggle-password-login i');
        if ($icon.hasClass('icon-down-dir')) {
            $icon.removeClass('icon-down-dir').addClass('icon-up-dir');
        } else {
            $icon.removeClass('icon-up-dir').addClass('icon-down-dir');
        }
    });

    // 5. Insertion de votre vue OIDC au tout début du modal-body
    const oidcView = new OidcLoginView({
        parentView: this,
        enablePasswordLogin: this.enablePasswordLogin
    }).render();
    
    this.$('.modal-body').prepend(oidcView.$el);

    return this;
});

/* Old version without toggle for password login
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
*/
export default OidcLoginView;
