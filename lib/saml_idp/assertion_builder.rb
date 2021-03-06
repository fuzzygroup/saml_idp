require 'builder'
require 'saml_idp/algorithmable'
require 'saml_idp/signable'
module SamlIdp
  class AssertionBuilder
    include Algorithmable
    include Signable
    attr_accessor :reference_id
    attr_accessor :issuer_uri
    attr_accessor :principal
    attr_accessor :audience_uri
    attr_accessor :saml_request_id
    attr_accessor :saml_acs_url
    attr_accessor :raw_algorithm
    attr_accessor :authn_context_classref
    attr_accessor :expiry
    attr_accessor :encryption_opts
    attr_accessor :skip_issuer
    attr_accessor :nest_subject_to_samlp
    attr_accessor :assertion_type

    delegate :config, to: :SamlIdp
    
    

    def initialize(reference_id, issuer_uri, principal, audience_uri, saml_request_id, saml_acs_url, raw_algorithm, authn_context_classref, expiry=60*60, encryption_opts=nil, skip_issuer=false, nest_subject_to_samlp = false, assertion_type = "mindtouch")
      self.reference_id = reference_id
      if skip_issuer
        # don't output the issuer as a standalone element; this matters to some SPs but not to others
      else
        self.issuer_uri = issuer_uri
      end
      self.principal = principal
      self.audience_uri = audience_uri
      self.saml_request_id = saml_request_id
      self.saml_acs_url = saml_acs_url
      self.raw_algorithm = raw_algorithm
      self.authn_context_classref = authn_context_classref
      self.expiry = expiry
      self.encryption_opts = encryption_opts
      self.nest_subject_to_samlp = nest_subject_to_samlp
      self.assertion_type = assertion_type
    end
    
    def fresh
      # if self.assertion_type == "lithium"
      #   raise "in lithium"
      # elsif self.assertion_type == "mindtouch"
      #   raise "in mindtouch"
      # end
      builder = Builder::XmlMarkup.new
      builder.Assertion xmlns: Saml::XML::Namespaces::ASSERTION,
        ID: reference_string,
        IssueInstant: now_iso,
        Version: "2.0" do |assertion|
          assertion.Issuer issuer_uri
          sign assertion
          assertion.Subject do |subject|
            subject.NameID name_id, Format: name_id_format[:name]
            subject.SubjectConfirmation Method: Saml::XML::Namespaces::Methods::BEARER do |confirmation|
              
              # turn off InResponseTo if its blank; problem with Lithium
              if saml_request_id.blank?
                confirmation.SubjectConfirmationData "",
                  NotOnOrAfter: not_on_or_after_subject,
                  Recipient: saml_acs_url
              else
                confirmation.SubjectConfirmationData "", InResponseTo: saml_request_id,
                  NotOnOrAfter: not_on_or_after_subject,
                  Recipient: saml_acs_url
              end
            end
          end
          assertion.Conditions NotBefore: not_before, NotOnOrAfter: not_on_or_after_condition do |conditions|
            conditions.AudienceRestriction do |restriction|
              restriction.Audience audience_uri
            end
          end
          if asserted_attributes
            assertion.AttributeStatement do |attr_statement|
              asserted_attributes.each do |friendly_name, attrs|
                attrs = (attrs || {}).with_indifferent_access
                attr_statement.Attribute Name: attrs[:name] || friendly_name,
                  NameFormat: attrs[:name_format] || Saml::XML::Namespaces::Formats::Attr::URI,
                  FriendlyName: friendly_name.to_s do |attr|
                    values = get_values_for friendly_name, attrs[:getter]
                    values.each do |val|
                      attr.AttributeValue val.to_s
                    end
                  end
              end
            end
          end
          assertion.AuthnStatement AuthnInstant: now_iso, SessionIndex: reference_string do |statement|
            statement.AuthnContext do |context|
              context.AuthnContextClassRef authn_context_classref
            end
          end
        end
    end
    alias_method :raw, :fresh
    private :fresh
    
    def fresh_1
      builder = Builder::XmlMarkup.new
      builder.tag!
      builder.tag!("saml:Assertion", {"xmlns:saml": Saml::XML::Namespaces::ASSERTION}) do |sa|
      end
    end

    def fresh0
      builder = Builder::XmlMarkup.new
      builder.tag!
      
      #builder.tag!("saml:Assertion", {"xmlns:saml": Saml::XML::Namespaces::ASSERTION}) do |sa|
        builder.Assertion "xmlns:saml": Saml::XML::Namespaces::ASSERTION,
          ID: reference_string,
          IssueInstant: now_iso,
          Version: "2.0" do |assertion|
            assertion.tag!("saml:Assertion") do |sa|
            assertion.Issuer issuer_uri
            sign assertion
            begin
              logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("ASSERTION_BUILDER.fresh before if");
            rescue StandardError => e
            end
            if nest_subject_to_samlp || 3 == 4
              begin
                logger = Logger.new("/var/www/apps/sso_portal/current/log/production.log"); logger.info("ASSERTION_BUILDER.fresh in if nest_subject_to_samlp");
              rescue StandardError => e
              end
            else
              #assertion.Subject do |subject|  
              
              #
              # THIS IS THE MAGIC BULLET TO REWRITING THIS 
              #
              assertion.tag!('saml:Subject', {}) do |subject|
                assertion.tag!('saml:NameID', {}) do |name_id|
                  subject.NameID name_id, Format: name_id_format[:name], xmlns: "urn:oasis:names:tc:SAML:2.0:assertion"
                
                  subject.SubjectConfirmation Method: Saml::XML::Namespaces::Methods::BEARER do |confirmation|
                    assertion.tag!("saml:SubjectConfirmationData", {}) do |sc|
                      confirmation.SubjectConfirmationData "", InResponseTo: saml_request_id,
                        NotOnOrAfter: not_on_or_after_subject,
                        Recipient: saml_acs_url
                    end
                  end
                end
              end
            end
            assertion.tag!('saml:Conditions', {}) do |condition|
              assertion.Conditions NotBefore: not_before, NotOnOrAfter: not_on_or_after_condition do |conditions|
                # xml.tag!('gp:contactGet') do
                #   xml.gp :contactID, "199434"
                # end
                conditions.AudienceRestriction do |restriction|
                  restriction.Audience audience_uri
                end
              end
            end
            if asserted_attributes
              assertion.AttributeStatement do |attr_statement|
                asserted_attributes.each do |friendly_name, attrs|
                  attrs = (attrs || {}).with_indifferent_access
                  attr_statement.Attribute Name: attrs[:name] || friendly_name,
                    NameFormat: attrs[:name_format] || Saml::XML::Namespaces::Formats::Attr::URI,
                    FriendlyName: friendly_name.to_s do |attr|
                      values = get_values_for friendly_name, attrs[:getter]
                      values.each do |val|
                        attr.AttributeValue val.to_s
                      end
                    end
                end
              end
            end
            assertion.AuthnStatement AuthnInstant: now_iso, SessionIndex: reference_string do |statement|
              statement.AuthnContext do |context|
                context.AuthnContextClassRef authn_context_classref
              end
            end
          end        
      end
    end
    alias_method :raw, :fresh
    private :fresh

    def encrypt(opts = {})
      raise "Must set encryption_opts to encrypt" unless encryption_opts
      raw_xml = opts[:sign] ? signed : raw
      require 'saml_idp/encryptor'
      encryptor = Encryptor.new encryption_opts
      encryptor.encrypt(raw_xml)
    end

    def asserted_attributes
      my_logger = Logger.new("#{Rails.root}/log/saml.log")
      my_logger.info("in asserted_attributes -- principal = #{principal}")
      my_logger.info("result of principal.respond_to?(:asserted_attributes) is #{principal.respond_to?(:asserted_attributes)}")
      if principal.respond_to?(:asserted_attributes)
        principal.send(:asserted_attributes)
      elsif !config.attributes.nil? && !config.attributes.empty?
        config.attributes
      end
    end
    private :asserted_attributes

    def get_values_for(friendly_name, getter)
      result = nil
      if getter.present?
        if getter.respond_to?(:call)
          result = getter.call(principal)
        else
          message = getter.to_s.underscore
          result = principal.public_send(message) if principal.respond_to?(message)
        end
      elsif getter.nil?
        message = friendly_name.to_s.underscore
        result = principal.public_send(message) if principal.respond_to?(message)
      end
      Array(result)
    end
    private :get_values_for

    def name_id
      name_id_getter.call principal
    end
    private :name_id

    def name_id_getter
      getter = name_id_format[:getter]
      if getter.respond_to? :call
        getter
      else
        ->(principal) { principal.public_send getter.to_s }
      end
    end
    private :name_id_getter

    def name_id_format
      @name_id_format ||= NameIdFormatter.new(config.name_id.formats).chosen
    end
    private :name_id_format

    def reference_string
      "_#{reference_id}"
    end
    private :reference_string

    def now
      @now ||= Time.now.utc
    end
    private :now

    def now_iso
      iso { now }
    end
    private :now_iso

    def not_before
      iso { now - 5 }
    end
    private :not_before

    def not_on_or_after_condition
      iso { now + expiry }
    end
    private :not_on_or_after_condition

    def not_on_or_after_subject
      iso { now + 3 * 60 }
    end
    private :not_on_or_after_subject

    def iso
      yield.iso8601
    end
    private :iso
  end
end
