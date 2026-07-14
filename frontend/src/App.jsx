import { Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Register from './pages/Register';
import Login from './pages/Login';
import './App.css';

function App() {
  return (
    <div className="app-container">

      <Navbar />
      
      <Routes>
        <Route path="/" element={<h2>Home / Product Catalog Page</h2>} />
        <Route path="/product/:id" element={<h2>Product Detail Page</h2>} />
        <Route path="/cart" element={<h2>Shopping Cart Page</h2>} />
        <Route path="/login" element={<Login/>} />
        <Route path="/register" element={<Register/>} />
      </Routes>
    </div>
  );
}

export default App;
