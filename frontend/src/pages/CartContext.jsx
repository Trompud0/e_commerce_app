import { createContext, useState, useEffect } from 'react';
import axios from 'axios';

// Create the actual context hook container
export const CartContext = createContext();

export function CartProvider({ children }) {
  const [cart, setCart] = useState([]);
  const [cartError, setCartError] = useState('');
  const [cartLoading, setCartLoading] = useState(false);

  // Helper function to dynamically grab the JWT token from storage and create the secure auth header
  const getAuthHeader = () => {
    const token = localStorage.getItem('token');
    return token ? { headers: { Authorization: `Bearer ${token}` } } : {};
  };

  // 1. Fetch the user's active cart rows from Postgres
  const fetchCart = async () => {
    const token = localStorage.getItem('token');
    if (!token) {
      setCart([]); // Clear state if logged out
      return;
    }
    
    try {
      setCartLoading(true);

      const response = await axios.get('http://localhost:3000/cart', getAuthHeader());
      setCart(response.data);
      
      setCartLoading(false);
    } catch (err) {
      setCartError('Could not sync shopping cart with server.');
      setCartLoading(false);
    }
  };

  // 2. Add an inventory item into the database cart
  const addToCart = async (productId, quantity = 1) => {
    try {
      const payload = { product_id: productId, quantity };

      const response = await axios.post('http://localhost:3000/cart', payload, getAuthHeader());
      fetchCart();
      
    } catch (err) {
      alert(err.response?.data?.message || 'Error inserting item to cart.');
    }
  };

  // Automatically fetch the cart once when the application boots up
  useEffect(() => {
    fetchCart();
  }, []);

  return (
    <CartContext value={{ cart, cartLoading, cartError, fetchCart, addToCart }}>
      {children}
    </CartContext>
  );
}

