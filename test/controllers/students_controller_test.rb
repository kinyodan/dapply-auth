require "test_helper"

class StudentsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @student = students(:one)
  end

  test "should get index" do
    get students_url, as: :json
    assert_response :success
  end

  # test "should create student" do
  #   assert_difference("Student.count") do
  #     post students_url, params: { student: { country_code: @student.country_code, country_id: @student.country_id, email: @student.email, first_name: @student.first_name, last_name: @student.last_name, location: @student.location, phone: @student.phone, second_name: @student.second_name } }, as: :json
  #   end

  #   assert_response :created
  # end

  # test "should show student" do
  #   get student_url(@student), as: :json
  #   assert_response :success
  # end

  # test "should update student" do
  #   patch student_url(@student), params: { student: { country_code: @student.country_code, country_id: @student.country_id, email: @student.email, first_name: @student.first_name, last_name: @student.last_name, location: @student.location, phone: @student.phone, second_name: @student.second_name } }, as: :json
  #   assert_response :success
  # end

  # test "should destroy student" do
  #   assert_difference("Student.count", -1) do
  #     delete student_url(@student), as: :json
  #   end

  #   assert_response :no_content
  # end
end
