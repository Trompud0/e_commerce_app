import { Link } from 'react-router-dom';
import './Navbar.css'; // We will create this file next!

function Navbar() {
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
        <li>
          <Link to="/login">Login</Link>
        </li>
        <li>
            <Link to="/register">Register</Link>
        </li>
      </ul>
    </nav>
  );
}

export default Navbar;
