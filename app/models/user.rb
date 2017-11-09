class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

 def self.create_with_password(attr={})
    generated_password = Devise.friendly_token.first(8)
    email = "LUCIFER@B.COM"
    self.create(attr.merge(email: email, password: generated_password, password_confirmation: generated_password))
 end

end
