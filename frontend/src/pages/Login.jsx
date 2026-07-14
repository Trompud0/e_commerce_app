import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { GoogleLogin } from '@react-oauth/google';

function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    // Try writing the code to send login details to the backend.
    try {
      const payload = {username, password};

      const response = await axios.post('http://localhost:3000/login', payload);
      const { token, user } = response.data;

      localStorage.setItem('token', token);
      console.log('Successfully logged in as:', user.username);
      navigate('/');

    } catch (err) {
      if (err.response && err.response.data && err.response.data.message) {
        setError(err.response.data.message);
      } else {
        setError('Something went wrong. Please try again.');
      }
    }
  };

  const handleGoogleSuccess = async (credentialResponse) => {
    try {
      const googleToken = credentialResponse.credential; 

      // Send the token payload across the network to our new backend route
      const response = await axios.post('http://localhost:3000/auth/google', { googleToken });
      
      const { token, user } = response.data;

      // Save our native application JWT to local storage and redirect home
      localStorage.setItem('token', token);
      console.log('Successfully logged in via Google as:', user.username);
      navigate('/');

    } catch (err) {
      if (err.response && err.response.data && err.response.data.message) {
        setError(err.response.data.message);
      } else {
        setError('Google Authentication failed. Please try again.');
      }
    }
  };

  return (
    <div style={{ maxWidth: '400px', margin: '0 auto', padding: '1rem' }}>
      <h2>Login to Your Account</h2>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      
      <form onSubmit={handleSubmit}>
        <div>
          <label>Username:</label>
          <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} required />
        </div>
        <div>
          <label>Password:</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </div>
        
        <button type="submit" style={{ marginTop: '1rem' }}>Login</button>
      </form>

      <div style={{ margin: '1.5rem 0', textAlign: 'center', color: '#666' }}>─ OR ─</div>

      <div style={{ display: 'flex', justifyContent: 'center' }}>
        <GoogleLogin
          onSuccess={handleGoogleSuccess}
          onError={() => setError('Google Authentication Failed')}
        />
      </div>
    </div>
  );
}

export default Login;
