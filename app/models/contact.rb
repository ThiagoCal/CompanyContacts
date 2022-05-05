class Contact < ApplicationRecord
  belongs_to :user
  paginates_per 50
  validates :name, :user, presence: true
end
