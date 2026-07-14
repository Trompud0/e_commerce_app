import { useState } from 'react';
import { useNavigate } from 'react-router-dom';  
import axios from 'axios';


function Register() {
  const navigate = useNavigate();

  // 1. We create state variables to hold form data
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [phone, setPhone] = useState('');
  const [address, setAddress] = useState('');
  const [error, setError] = useState('');


  // This function runs when the user clicks "Submit"
  const handleSubmit = async (e) => {
    e.preventDefault(); // Prevents the page from refreshing
    setError(''); // Clears old errors

    // Sends this data to your backend.
    try {
      const payload = {username, email, password, phone, address};

      const response = await axios.post('http://localhost:3000/registration', payload);
      const { token, user } = response.data;
      
      localStorage.setItem('token', token);
      console.log('Successfully registered and logged in as:', user.username);
      navigate('/');

    } catch (err) {
      if (err.response && err.response.data && err.response.data.message) {
        setError(err.response.data.message);
      } else {
        console.log('Something went wrong. Please try again.');
      }
    }
  };

  return (
    <div style={{ maxWidth: '400px', margin: '0 auto', padding: '1rem' }}>
      <h2>Create an Account</h2>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      
      <form onSubmit={handleSubmit}>
        <div>
          <label>Username:</label>
          <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} required />
        </div>
        <div>
          <label>Email:</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </div>
        <div>
          <label>Password:</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </div>
        <div>
          <label>Phone:</label>
          <input type="text" value={phone} onChange={(e) => setPhone(e.target.value)} required />
        </div>
        <div>
          <label>Address:</label>
          <input type="text" value={address} onChange={(e) => setAddress(e.target.value)} required />
        </div>
        
        <button type="submit" style={{ marginTop: '1rem' }}>Register</button>
      </form>
    </div>
  );
}

export default Register;
