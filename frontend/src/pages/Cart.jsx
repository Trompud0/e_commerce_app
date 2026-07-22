import { useEffect, useContext } from 'react';
import { CartContext

 } from './CartContext';
import { Link } from 'react-router-dom';
import axios from 'axios';

function Cart() {

  const { cart, cartLoading, cartError, fetchCart } = useContext(CartContext);

  // Re-sync with the database to make sure we show the freshest cart rows on load
  useEffect(() => {
    fetchCart();
  }, []);

  // Calculate the ultimate total of the entire checkout basket
  const calculateCartTotal = () => {
    return cart.reduce((total, item) => total + Number(item.subtotal), 0).toFixed(2);
  };

  // Handler to clear a single item row from the cart database table
  const handleRemoveItem = async (cartItemId) => {
    try {
      const token = localStorage.getItem('token');
      // Execute a DELETE request to your backend endpoint: /cart/:itemId
      await axios.delete(`http://localhost:3000/cart/${cartItemId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      // Refresh our global state layout instantly after deleting the row
      fetchCart();
    } catch (err) {
      alert('Failed to remove item from cart.');
    }
  };

  if (cartLoading) return <div style={{ textAlign: 'center', marginTop: '3rem' }}>Reviewing your checkout basket...</div>;
  if (cartError) return <div style={{ textAlign: 'center', color: 'red', marginTop: '3rem' }}>{cartError}</div>;

  return (
    <div style={{ maxWidth: '800px', margin: '2rem auto', padding: '1rem' }}>
      <h2>Your Shopping Cart 🛒</h2>
      
      {cart.length === 0 ? (
        <div style={{ textAlign: 'center', marginTop: '2rem' }}>
          <p>Your cart is empty!</p>
          <Link to="/" style={{ color: '#00adb5' }}>Go browse our product inventory</Link>
        </div>
      ) : (
        <div>
          {/* Loop over your live database rows */}
          {cart.map((item) => (
            <div key={item.cart_item_id} style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              borderBottom: '1px solid #ddd', padding: '1rem 0'
            }}>
              <div>
                <h3 style={{ margin: '0 0 0.5rem 0' }}>{item.product_name}</h3>
                <p style={{ margin: 0, color: '#666' }}>
                  Price: ${Number(item.price).toFixed(2)} | Qty: {item.quantity}
                </p>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
                <span style={{ fontWeight: 'bold', fontSize: '1.1rem' }}>
                  ${Number(item.subtotal).toFixed(2)}
                </span>
                <button 
                  onClick={() => handleRemoveItem(item.cart_item_id)}
                  style={{
                    backgroundColor: '#ff4d4d', color: 'white', border: 'none',
                    borderRadius: '4px', padding: '0.4rem 0.8rem', cursor: 'pointer'
                  }}
                >
                  Remove
                </button>
              </div>
            </div>
          ))}

          {/* Checkout Total Module */}
          <div style={{ marginTop: '2rem', textComponent: 'right', display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
            <h3>Total: ${calculateCartTotal()}</h3>
            
            {/* We will route this to Stripe payments during Phase 5 */}
            <button style={{
              marginTop: '1rem', padding: '0.8rem 2rem', backgroundColor: '#00adb5',
              color: 'white', border: 'none', borderRadius: '4px', fontComponent: '1.1rem',
              fontWeight: 'bold', cursor: 'pointer'
            }}>
              Proceed to Checkout 💳
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default Cart;
