import OidcLoginView from './OidcLoginView';

const LoginView = girder.views.layout.LoginView;
const { wrap } = girder.utilities.PluginUtils;

wrap(LoginView, 'render', function (render) {
    render.call(this);
    new OidcLoginView({
        el: this.$('.modal-body'),
        parentView: this
    }).render();
    return this;
});
