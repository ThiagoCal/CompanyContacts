# Provided that trusted users use an HTTP request header named APIKey
Rack::Attack.safelist("mark any authenticated access safe") do |request|
  # Requests are allowed if the return value is truthy
  request.env["HTTP_APIKEY"] == "secret-string"
end

# Always allow requests from localhost
# (blocklist & throttles are skipped)
Rack::Attack.safelist('allow from localhost') do |req|
  # Requests are allowed if the return value is truthy
  '127.0.0.1' == req.ip || '::1' == req.ip
end

Rack::Attack.throttle("requests by ip", limit: 5, period: 2) do |request|
  request.ip
end

# Throttle login attempts for a given email parameter to 6 reqs/minute
# Return the *normalized* email as a discriminator on POST /login requests
Rack::Attack.throttle('limit logins per email', limit: 6, period: 60) do |req|
  if req.path == '/login' && req.post?
    # Normalize the email, using the same logic as your authentication process, to
    # protect against rate limit bypasses.
    req.params['email'].to_s.downcase.gsub(/\s+/, "")
  end
end
