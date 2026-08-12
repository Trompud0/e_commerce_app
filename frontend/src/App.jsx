import { Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Register from './pages/Register';
import Login from './pages/Login';
import Home from './pages/Home';
import ProductDetail from './pages/ProductDetail';
import Cart from './pages/Cart';
import Checkout from './pages/Checkout';
import Orders from './pages/Orders';
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
        <Route path="/" element={<Home/>} />
        <Route path="/product/:id" element={<ProductDetail/>} />
        <Route path="/cart" element={<Cart />} />
        <Route path="/login" element={<Login setIsLoggedIn={setIsLoggedIn}/>} />
        <Route path="/register" element={<Register setIsLoggedIn={setIsLoggedIn}/>} />
        {/* Protected Checkout Route */}
        <Route 
          path="/checkout" 
          element={isLoggedIn ? <Checkout /> : <Navigate to="/login" replace />} 
        />

        {/* Protected Orders Route */}
        <Route 
          path="/orders" 
          element={isLoggedIn ? <Orders /> : <Navigate to="/login" replace />} 
        />
      </Routes>
    </div>
  );
}

export default App;
