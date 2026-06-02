import '../stylesheets/userAccountView.styl';

const UserAccountView = girder.views.body.UserAccountView;
const { wrap } = girder.utilities.PluginUtils;

function isExternallyManaged(user) {
    const oidc = user && user.get('oidc');
    return Array.isArray(oidc) && oidc.length > 0;
}

// For OIDC-linked accounts the identity provider owns the profile, password,
// and two-factor settings. Hide the corresponding controls. The server-side
// guards in account_guard.py are the actual enforcement; this is just UX.
// The profile lockdown applies to anyone viewing the page, including a site
// admin looking at someone else's account: those edits are rejected too.
wrap(UserAccountView, 'render', function (render) {
    render.call(this);

    if (isExternallyManaged(this.user)) {
        this.$('#g-email, #g-firstName, #g-lastName').prop('disabled', true);
        this.$('#g-user-info-form button[type="submit"]').remove();
        if (!this.$('.g-oidc-managed-note').length) {
            this.$('#g-user-info-form').prepend(
                '<p class="g-oidc-managed-note">This profile is managed by the '
                + 'user\'s identity provider and cannot be edited here.</p>');
        }

        // Password changes and two-factor auth are handled by the provider.
        this.$('.g-account-tabs a[name="password"]').closest('li').remove();
        this.$('.g-account-tabs a[name="otp"]').closest('li').remove();
        this.$('#g-account-tab-password, #g-account-tab-otp').remove();
    }

    return this;
});
