class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
        :recoverable, :rememberable, :validatable

      enum :roles, [:normal, :admin, :proadmin], _default: 'user'
      validates :email, presence: true
end
 #usuario normal
 before_action only: [:index, :show] do
  authorize_request(["normal", "admin"])
end
#usuario admin
before_action only: [:new, :edit, :create, :update] do
  authorize_request(["admin" "proadmin"])
end
#usuario proadmin
before_action only: [:destroy] do
  authorize_request(["proadmin"])
end
