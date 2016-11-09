# encoding: utf-8
module SamlIdp
  class IdpController < ActionController::Base
    include SamlIdp::Controller

    unloadable unless Rails::VERSION::MAJOR >= 4
    protect_from_forgery
    before_filter :validate_saml_request, only: [:new, :create]

    def new
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM IDP_CONTROLLER :: new");
      
      render template: "saml_idp/idp/new"
    end

    def show
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM IDP_CONTROLLER :: show");
      render xml: SamlIdp.metadata.signed
    end

    def create
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM IDP_CONTROLLER :: create");
      
      unless params[:email].blank? && params[:password].blank?
        person = idp_authenticate(params[:email], params[:password])
        if person.nil?
          @saml_idp_fail_msg = "Incorrect email or password."
        else
          @saml_response = idp_make_saml_response(person)
          render :template => "saml_idp/idp/saml_post", :layout => false
          return
        end
      end
      render :template => "saml_idp/idp/new"
    end

    def logout
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM IDP_CONTROLLER :: logout");
      
      idp_logout
      @saml_response = idp_make_saml_response(nil)
      render :template => "saml_idp/idp/saml_post", :layout => false
    end

    def idp_logout
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM IDP_CONTROLLER :: idp_logout");
      
      raise NotImplementedError
    end
    private :idp_logout

    def idp_authenticate(email, password)
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM IDP_CONTROLLER :: idp_authenticate");
      
      raise NotImplementedError
    end
    protected :idp_authenticate

    def idp_make_saml_response(person)
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM IDP_CONTROLLER :: idp_make_saml_response");
      
      raise NotImplementedError
    end
    protected :idp_make_saml_response
  end
end
