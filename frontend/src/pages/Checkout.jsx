import React, { useContext, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { CartContext } from './CartContext';
import axios from 'axios';

export default function Checkout() {
  const { cart, cartLoading, cartError, fetchCart } = useContext(CartContext);
  const [checkoutLoading, setCheckoutLoading] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const navigate = useNavigate();

  // Reuses your clean logic directly from Cart.jsx to keep numbers perfectly in sync
  const calculateCartTotal = () => {
    return cart.reduce((total, item) => total + Number(item.subtotal), 0).toFixed(2);
  };

  const getAuthHeader = () => {
    const token = localStorage.getItem('token');
    return token ? { headers: { Authorization: `Bearer ${token}` } } : {};
  };

  const handleCheckout = async () => {
    setCheckoutLoading(true);
    setErrorMessage('');
    setSuccessMessage('');

    try {
      // Backend automatically pulls, acts on, and clears your user cart tables
      const response = await axios.post('http://localhost:3000/checkout', {}, getAuthHeader());
      
      setSuccessMessage(`Checkout complete! Order ID: ${response.data.orderId}`);
      
      // Wipe the global context cart since backend tables are now empty
      await fetchCart();

      // Redirect out to history after success confirmation
      setTimeout(() => {
        navigate('/orders');
      }, 2000);

    } catch (err) {
      setErrorMessage(err.response?.data?.error || err.response?.data?.message || 'Checkout failed.');
    } finally {
      setCheckoutLoading(false);
    }
  };

  if (cartLoading) return <div style={{ textAlign: 'center', marginTop: '3rem' }}>Reviewing your checkout details...</div>;
  if (cartError) return <div style={{ textAlign: 'center', color: 'red', marginTop: '3rem' }}>{cartError}</div>;
  if (cart.length === 0 && !successMessage) return <div style={{ textAlign: 'center', marginTop: '3rem' }}>Your cart is empty.</div>;

  return (
    <div style={{ maxWidth: '600px', margin: '2rem auto', padding: '1rem' }}>
      <h2>Confirm Your Order 📦</h2>
      
      {/* 1. Verified Cart Items List */}
      <div style={{ marginBottom: '2rem' }}>
        {cart.map((item) => (
          <div key={item.cart_item_id} style={{ 
            display: 'flex', justifyContent: 'space-between', 
            borderBottom: '1px solid #ddd', padding: '1rem 0' 
          }}>
            <div>
              <h4 style={{ margin: '0 0 0.2rem 0' }}>{item.product_name}</h4>
              <p style={{ margin: 0, color: '#666', fontSize: '0.9rem' }}>
                Qty: {item.quantity} × ${Number(item.price).toFixed(2)}
              </p>
            </div>
            <span style={{ fontWeight: 'bold' }}>
              ${Number(item.subtotal).toFixed(2)}
            </span>
          </div>
        ))}
      </div>

      {/* 2. Total Display */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem' }}>
        <h3>Total Due:</h3>
        <h3 style={{ color: '#00adb5' }}>${calculateCartTotal()}</h3>
      </div>

      {/* 3. Operational Feedback */}
      {errorMessage && <p style={{ color: 'red', fontWeight: 'bold', marginTop: '1rem' }}>{errorMessage}</p>}
      {successMessage && <p style={{ color: 'green', fontWeight: 'bold', marginTop: '1rem' }}>{successMessage} (Redirecting...)</p>}

      {/* 4. Submission Control */}
      <button 
        onClick={handleCheckout} 
        disabled={checkoutLoading || cart.length === 0}
        style={{
          marginTop: '1.5rem', width: '100%', padding: '0.8rem', 
          backgroundColor: '#00adb5', color: 'white', border: 'none', 
          borderRadius: '4px', fontSize: '1.1rem', fontWeight: 'bold', 
          cursor: checkoutLoading ? 'not-allowed' : 'pointer',
          opacity: checkoutLoading ? 0.7 : 1
        }}
      >
        {checkoutLoading ? 'Processing Secure Order...' : 'Place Order'}
      </button>
    </div>
  );
}
