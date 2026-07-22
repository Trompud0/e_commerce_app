import { Link, useNavigate } from 'react-router-dom';
import './Navbar.css'; 
import { useContext } from 'react';
import { CartContext } from '../pages/CartContext';

function Navbar({isLoggedIn, setIsLoggedIn}) {
  const navigate = useNavigate();

  const { cart } = useContext(CartContext);

  const handleLogout = () => {
    localStorage.removeItem('token');

    setIsLoggedIn(false);

    navigate('/login');
  };

  const getCartItemCount = () => {
    return cart.reduce((total, item) => total + item.quantity, 0);
  }

  return (
    <nav className="navbar">
      <div className="navbar-logo">
        <Link to="/">🛍️ MyStore</Link>
      </div>
      <ul className="navbar-links">
        <li>
          <Link to="/">Products</Link>
        </li>
        
        <li>
          <Link to="/cart" className="cart-link">
            Cart 🛒 
            {getCartItemCount() > 0 && (
              <span className="cart-badge">{getCartItemCount()}</span>
            )}
          </Link>
        </li>

        {isLoggedIn ? (
          <li>
            <button onClick={handleLogout} className='logout-btn'>Logout</button>
          </li>  
        ) : (
            <>
              <li><Link to="/login">Login</Link></li>
              <li><Link to="/register">Register</Link></li>
            </>
        )}
      </ul>
    </nav>
  );
}

export default Navbar;
