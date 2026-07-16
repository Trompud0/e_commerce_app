import { Link, useNavigate } from 'react-router-dom';
import './Navbar.css'; // We will create this file next!

function Navbar({isLoggedIn, setIsLoggedIn}) {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('token');

    setIsLoggedIn(false);

    navigate('/login');
  };

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
          <Link to="/cart">Cart 🛒</Link>
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
