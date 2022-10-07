class BaseController < ApplicationController
    before_action :verify_authentication , only: %i[ create ]


    def verify_authentication
	  	if request.headers['HTTP_AUTHORIZATION']

	    	header_params = eval(request.headers['HTTP_AUTHORIZATION'])
	   		decoded_response = decrypt(header_params[:token], 'hmac_secret_key', 'HS256')
	   		p decoded_response
		    if (@user = User.find_by_jti(decoded_response[:jti]))
		      role_user = @user.has_role? :student
		      role_admin = @user.has_role? :admin
		      @student = Student.where(email: @user.email).first

		      if role_user && !role_admin
		        render json: { status: true, role_student: role_user, id: @student.uuid, message: 'User Authenticated ' }
		      end

		      if role_admin
		        render json: { status: true, role_admin: role_admin, message: 'User Authenticated ' }
		      end

		    else
		      render json: { data: :unauthorized, status: :false, message: 'user failed logged in wrong token' }
		    end
		else 
			header_params = eval(request.headers['HTTP_AUTHORIZATION'])
			p header_params
		   render json: { data: :unauthorized, status: :false, message: 'user failed Authentication no token' }  

	  	end
    end

  protected

  def encrypt(payload, salt, algo = 'HS256')
    JWT.encode payload, salt, algo
  end

  def decrypt(token, salt, algo = 'HS256')
    decrypted_token = JWT.decode token, salt, algo
    decrypted_token.first.deep_symbolize_keys rescue {}
  end

end
