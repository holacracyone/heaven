# A bunch of validations for incoming webhooks to ensure github is sending them
module WebhookValidations
  extend ActiveSupport::Concern

  def verify_incoming_webhook_address!
    if valid_incoming_webhook_address?
      true
    else
      render :json => {}, :status => :forbidden
    end
  end

  def valid_incoming_webhook_address?
    if ENV["HEAVEN_KUBERNETES"]
      Rails.logger.debug "running from within Kubernetes, allowing non-Github ip addresses"
      return true
    end
    if Octokit.api_endpoint == "https://api.github.com/"
      GithubSourceValidator.new(request.ip).valid?
    else
      true
    end
  end

  def verify_secret!
    if valid_payload_signature?
      true
    else
      Rails.logger.warn "Signatures didn't match!"
      render :json => {}, :status => :forbidden
    end
  end

  def valid_payload_signature?
    unless secret = ENV['HEAVEN_WEBHOOK_SECRET']
      Rails.logger.warn "HEAVEN_WEBHOOK_SECRET environment variable not set, skipping signature verification"
      return true
    end
    request.body.rewind
    payload_body = request.body.read
    signature = 'sha1=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'), secret, payload_body)
    Rack::Utils.secure_compare(signature, request.env['HTTP_X_HUB_SIGNATURE'])
  end
end
