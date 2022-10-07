Rails.application.routes.draw do

  # devise_for :users
  namespace :api do
    namespace :v1 do
      resources :student_applications
      resources :applications
      resources :students
      get '/student_applications_list', to: 'student_applications#student_applications_list'
      post '/soft_destroy', to: 'student_applications#soft_destroy'
      resources :sessions , only: [:create ,:destroy]
      post '/verify_authentication' , to: 'sessions#verify_authentication'
      post '/verify_authentication_rpc', to: 'sessions#verify_authentication_rpc'
      resources :institutions
      get  '/dashboard_data', to: 'dashboard#index'
      resources :appointments
    end
  end
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Defines the root path route ("/")
  # root "articles#index"
end
