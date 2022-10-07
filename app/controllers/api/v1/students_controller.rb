class Api::V1::StudentsController < ApplicationController
  before_action :set_student, only: %i[  update destroy ]
  before_action :set_student_by_uuid, only: %i[ show update destroy applications ]

  # GET /students
  def index
    @students = Student.all
    render json: {data: @students, status: true ,message: "Students listed "}
  end

  # GET /students/1
  def show
    @applications = StudentApplication.where(student_id: @student_by_uuid.id)
    render json: { status: true, message: "student details listed", student: @student_by_uuid, applications: @applications}
  end

  def applications
    @applications = StudentApplication.where(student_id: @student_by_uuid.id)
    p @student_by_uuid.id
    render json: { student: @student, applications: @applications }, status: :created, location: @student
  end

  # POST /students
  def create
    header_params = eval(request.headers['HTTP_AUTHORIZATION'])
    p header_params[:password]
    @student_present = Student.where(email: header_params[:email]).first
    @student_user_present =  User.where(email: header_params[:email]).first

    if @student_present && @student_user_present
      render json: "Email already exists" , status: false , data: :unprocessable_entity
    else
      @student = Student.new(student_params)
      if @student.save
        render json: {message: "Sign up successfull", status: true , data: @student}
      else
        render json: @student.errors, status: false , data: :unprocessable_entity
      end
    end

  end

  # PATCH/PUT /students/1
  def update
    if @student.update(student_params)
      render json: @student
    else
      render json: @student.errors, status: :unprocessable_entity
    end
  end

  # DELETE /students/1
  def destroy
    @student.destroy
  end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_student
      @student = Student.find(params[:id])
    end

    def check_admin
     # @admin_user =  User.find(params[:user])
    end

    def set_student_by_uuid
     @student_by_uuid = Student.find_by(uuid: params[:id])
     p "student by uuid listed"
    end
    
    # Only allow a list of trusted parameters through.
    def student_params
      params.permit(:first_name, :second_name, :last_name, :phone, :email, :location, :country_id, :country_code,:status, :password, :confirm_password)
    end
    
    def student_params_clean
      params.permit(:first_name, :second_name, :last_name, :phone, :email, :location, :country_id, :country_code,:status)
    end

end
