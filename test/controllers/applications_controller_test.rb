# require "test_helper"

# class ApplicationsControllerTest < ActionDispatch::IntegrationTest
#   setup do
#     @application = applications(:one)
#     p @application
#   end

#   test "should get index" do
#     get applications_url, as: :json
#     assert_response :success
#   end

#   test "should create application" do
#     assert_difference("Application.count") do
#       post applications_url, params: { application: { applicatio_admin: @application.applicatio_admin, bank_statement: @application.bank_statement, confirmation_of_acceptance: @application.confirmation_of_acceptance, current_agent_processing: @application.current_agent_processing, current_step: @application.current_step, cv: @application.cv, degree_certificate: @application.degree_certificate, degree_transcript: @application.degree_transcript, ksce_cert: @application.ksce_cert, passport: @application.passport, passport_copy: @application.passport_copy, personal_statement: @application.personal_statement, previous_visa: @application.previous_visa, progress_state: @application.progress_state, progress_steps: @application.progress_steps, recommendation_letters: @application.recommendation_letters, school_leaving: @application.school_leaving, status: @application.status, student_id: @application.student_id, upload_by: @application.upload_by, uuid: @application.uuid, visa_refusals: @application.visa_refusals, workflow_state: @application.workflow_state, workflow_status: @application.workflow_status, worklow_progress: @application.worklow_progress } }, as: :json
#     end

#     assert_response :created
#   end

#   test "should show application" do
#     get application_url(@application), as: :json
#     assert_response :success
#   end

#   # test "should update application" do
#   #   patch application_url(@application), params: { application: { applicatio_admin: @application.applicatio_admin, bank_statement: @application.bank_statement, confirmation_of_acceptance: @application.confirmation_of_acceptance, current_agent_processing: @application.current_agent_processing, current_step: @application.current_step, cv: @application.cv, degree_certificate: @application.degree_certificate, degree_transcript: @application.degree_transcript, ksce_cert: @application.ksce_cert, passport: @application.passport, passport_copy: @application.passport_copy, personal_statement: @application.personal_statement, previous_visa: @application.previous_visa, progress_state: @application.progress_state, progress_steps: @application.progress_steps, recommendation_letters: @application.recommendation_letters, school_leaving: @application.school_leaving, status: @application.status, student_id: @application.student_id, upload_by: @application.upload_by, uuid: @application.uuid, visa_refusals: @application.visa_refusals, workflow_state: @application.workflow_state, workflow_status: @application.workflow_status, worklow_progress: @application.worklow_progress } }, as: :json
#   #   assert_response :success
#   # end

#   test "should destroy application" do
#     assert_difference("Application.count", -1) do
#       delete application_url(@application), as: :json
#     end

#     assert_response :no_content
#   end
# end
