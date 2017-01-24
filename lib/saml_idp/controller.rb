# encoding: utf-8
require 'openssl'
require 'base64'
require 'time'
require 'uuid'
require 'saml_idp/request'
require 'saml_idp/logout_response_builder'
module SamlIdp
  module Controller
    extend ActiveSupport::Concern

    included do
      helper_method :saml_acs_url if respond_to? :helper_method
    end

    attr_accessor :algorithm
    attr_accessor :saml_request

    protected

    def validate_saml_request(raw_saml_request = params[:SAMLRequest])
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM CONTROLLER :: validate_saml_request");
      
      decode_request(raw_saml_request)
      render nothing: true, status: :forbidden unless valid_saml_request?
    end

    def decode_request(raw_saml_request)
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM CONTROLLER :: decode_request");
      self.saml_request = Request.from_deflated_request(raw_saml_request)
    end

    def authn_context_classref
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM CONTROLLER :: authn_context_classref");
      
      Saml::XML::Namespaces::AuthnContext::ClassRef::PASSWORD
    end

    def encode_authn_response(principal, opts = {})
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM CONTROLLER :: encode_authn_response");
      
      response_id = get_saml_response_id
      reference_id = opts[:reference_id] || get_saml_reference_id
      audience_uri = opts[:audience_uri] || saml_request.issuer || saml_acs_url[/^(.*?\/\/.*?\/)/, 1]
      opt_issuer_uri = opts[:issuer_uri] || issuer_uri
      my_authn_context_classref = opts[:authn_context_classref] || authn_context_classref
      expiry = opts[:expiry] || 60*60
      encryption_opts = opts[:encryption] || nil

      SamlResponse.new(
        reference_id,
        response_id,
        opt_issuer_uri,
        principal,
        audience_uri,
        saml_request_id,
        saml_acs_url,
        (opts[:algorithm] || algorithm || default_algorithm),
        my_authn_context_classref,
        expiry,
        encryption_opts
      ).build
    end

    def encode_logout_response(principal, opts = {})
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM CONTROLLER :: encode_logout_response");
      
      SamlIdp::LogoutResponseBuilder.new(
        get_saml_response_id,
        (opts[:issuer_uri] || issuer_uri),
        saml_logout_url,
        saml_request_id,
        (opts[:algorithm] || algorithm || default_algorithm)
      ).signed
    end

    def encode_response(principal, opts = {})
      logger = Logger.new("/var/www/apps/sso_portal/current/log/saml_idp.log"); 
      logger.info("GEM CONTROLLER :: encode_response");
      logger.info("GEM CONTROLLER :: encode_response :: principal = #{principal}");
      logger.info("GEM CONTROLLER :: encode_response :: opts = #{opts}");
      
      if saml_request && saml_request.authn_request?
        encode_authn_response(principal, opts)
      elsif saml_request && saml_request.logout_request?
        encode_logout_response(principal, opts)
      # else
      else
        # 1/24 -- removed raise to be safe 
        # default it to a logout response
        encode_logout_response(principal, opts)
        
        #raise "Unknown request: #{saml_request}"
        #raise "Unknown request: #{saml_request} -- principal = #{principal} -- opts = #{opts}"
        # c97856673b3017649492353fa493870a35cd4e6e
      end
    end

    def issuer_uri
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM CONTROLLER :: issuer_uri");
      
      (SamlIdp.config.base_saml_location.present? && SamlIdp.config.base_saml_location) ||
        (defined?(request) && request.url.to_s.split("?").first) ||
        "http://example.com"
    end

    def valid_saml_request?
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM CONTROLLER :: valid_saml_request?");
      
      saml_request.valid?
    end

    def saml_request_id
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM CONTROLLER :: saml_request_id");
      
      saml_request.request_id
    end

    def saml_acs_url
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM CONTROLLER :: saml_acs_url");
      
      saml_request.acs_url
    end

    def saml_logout_url
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM CONTROLLER :: saml_logout_url");
      
      saml_request.logout_url
    end

    def get_saml_response_id
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM CONTROLLER :: get_saml_response_id");
      
      "a" + UUID.generate
    end

    def get_saml_reference_id
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM CONTROLLER :: get_saml_reference_id");
      
      "a" + UUID.generate
    end

    def default_algorithm
      logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("GEM CONTROLLER :: default_algorithm");
      
      OpenSSL::Digest::SHA256
    end
  end
end
