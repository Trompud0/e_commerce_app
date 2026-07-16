import { Routes, Route } from 'react-router-dom';
import { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Register from './pages/Register';
import Login from './pages/Login';
import './App.css';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('token');
    setIsLoggedIn(!!token);
  }, []);

  return (
    <div className="app-container">

      <Navbar isLoggedIn={isLoggedIn} setIsLoggedIn={setIsLoggedIn} />
      
      <Routes>
        <Route path="/" element={<h2>Home / Product Catalog Page</h2>} />
        <Route path="/product/:id" element={<h2>Product Detail Page</h2>} />
        <Route path="/cart" element={<h2>Shopping Cart Page</h2>} />
        <Route path="/login" element={<Login setIsLoggedIn={setIsLoggedIn}/>} />
        <Route path="/register" element={<Register setIsLoggedIn={setIsLoggedIn}/>} />
      </Routes>
    </div>
  );
}

export default App;
