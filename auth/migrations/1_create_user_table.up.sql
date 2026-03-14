-- Users table
CREATE TABLE users (
                       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                       name VARCHAR(255) NOT NULL,
                       email VARCHAR(255) UNIQUE NOT NULL,
                       email_verified BOOLEAN DEFAULT false,
                       password_hash VARCHAR(255) NOT NULL,
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- Create email_verifications table
CREATE TABLE email_verifications (
                                     id SERIAL PRIMARY KEY,
                                     user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                     token VARCHAR(64) NOT NULL UNIQUE,
                                     expires_at TIMESTAMP NOT NULL,
                                     created_at TIMESTAMP DEFAULT NOW()
);


-- Sessions table
CREATE TABLE sessions (
                          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                          token VARCHAR(255) UNIQUE NOT NULL,
                          expires_at TIMESTAMP NOT NULL,
                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- API Keys table
CREATE TABLE api_keys (
                          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                          key VARCHAR(255) UNIQUE NOT NULL,
                          name VARCHAR(255) NOT NULL,
                          is_active BOOLEAN DEFAULT true,
                          last_used_at TIMESTAMP,
                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Usage tracking table
CREATE TABLE usage (
                       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                       api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
                       user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                       endpoint VARCHAR(255) NOT NULL,
                       method VARCHAR(10) NOT NULL,
                       status_code INTEGER NOT NULL,
                       requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for better performance

CREATE INDEX idx_sessions_token ON sessions(token);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_api_keys_key ON api_keys(key);
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_usage_user_id ON usage(user_id);
CREATE INDEX idx_usage_requested_at ON usage(requested_at);
CREATE INDEX idx_usage_api_key_id ON usage(api_key_id);
CREATE INDEX idx_email_verifications_token ON email_verifications(token);
CREATE INDEX idx_email_verifications_user_id ON email_verifications(user_id);