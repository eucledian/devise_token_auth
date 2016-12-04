module DeviseTokenAuth
  class ConfirmationsController < DeviseTokenAuth::ApplicationController
    # Confirms a given device resource identified by the given
    # +confirmation_token+ parameter generated in a signup proccess.
    # If resource is confirmed successfully, an empty HTTP body is returned and
    # a status code of 200 is returned.
    # According exceptions are thrown if an invalid +confirmation_token+ is
    # specified.
    #
    # GET /resource/confirmation
    # @param [String] [confirmation_token] - resource +confirmation_token+
    # @return [nil] empty response
    def show
      @resource = resource_class.confirm_by_token(params[:confirmation_token])

      if @resource and @resource.id
        # create client id
        client_id  = SecureRandom.urlsafe_base64(nil, false)
        token      = SecureRandom.urlsafe_base64(nil, false)
        token_hash = BCrypt::Password.create(token)
        expiry     = (Time.now + DeviseTokenAuth.token_lifespan).to_i

        @resource.tokens[client_id] = {
          token:  token_hash,
          expiry: expiry
        }

        @resource.save!

        render body: nil, status: 200
      else
        raise ActionController::RoutingError.new('Not Found')
      end
    end
  end
end
