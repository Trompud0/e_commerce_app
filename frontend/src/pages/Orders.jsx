import React, { useEffect, useState } from 'react';
import axios from 'axios';

export default function Orders() {
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Track detailed data and loading states for individual expanded order cards
  const [expandedOrders, setExpandedOrders] = useState({}); // e.g. { orderId: [items...] }
  const [detailsLoading, setDetailsLoading] = useState({});  // e.g. { orderId: true/false }

  const getAuthHeader = () => {
    const token = localStorage.getItem('token');
    return token ? { headers: { Authorization: `Bearer ${token}` } } : {};
  };

  // Fetch the master summary list of all past orders
  useEffect(() => {
    const fetchOrders = async () => {
      try {
        const response = await axios.get('http://localhost:3000/orders', getAuthHeader());
        setOrders(response.data);
      } catch (err) {
        setError(err.response?.data?.message || 'Failed to download purchase history.');
      } finally {
        setLoading(false);
      }
    };

    fetchOrders();
  }, []);

  // Fetch individual item lists only when a user expands a card
  const toggleOrderDetails = async (orderId) => {
    // If already open, close it by removing the key
    if (expandedOrders[orderId]) {
      const updatedExpanded = { ...expandedOrders };
      delete updatedExpanded[orderId];
      setExpandedOrders(updatedExpanded);
      return;
    }

    try {
      setDetailsLoading(prev => ({ ...prev, [orderId]: true }));
      
      const response = await axios.get(`http://localhost:3000/orders/${orderId}`, getAuthHeader());
      
      // Store the fetched line items mapped to their specific order ID
      setExpandedOrders(prev => ({ ...prev, [orderId]: response.data }));
    } catch (err) {
      alert('Could not retrieve details for this order.');
    } finally {
      setDetailsLoading(prev => ({ ...prev, [orderId]: false }));
    }
  };

  if (loading) return <div style={{ textAlign: 'center', marginTop: '3rem' }}>Loading order logs...</div>;
  if (error) return <div style={{ textAlign: 'center', color: 'red', marginTop: '3rem' }}>{error}</div>;

  return (
    <div style={{ maxWidth: '800px', margin: '2rem auto', padding: '1rem' }}>
      <h2>Your Order History 📜</h2>
      
      {orders.length === 0 ? (
        <p style={{ textAlign: 'center', marginTop: '2rem' }}>You haven't placed any orders yet!</p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {orders.map((order) => {
            const isExpanded = !!expandedOrders[order.id];
            const isLoadingDetails = detailsLoading[order.id];

            return (
              <div 
                key={order.id} 
                style={{
                  border: '1px solid #ddd',
                  borderRadius: '6px',
                  padding: '1rem',
                  backgroundColor: '#f9f9f9'
                }}
              >
                {/* Master summary row */}
                <div style={{ 
                  display: 'flex', 
                  justifyContent: 'space-between', 
                  alignItems: 'center' 
                }}>
                  <div>
                    <h3 style={{ margin: '0 0 0.3rem 0' }}>Order #{order.id}</h3>
                    <p style={{ margin: 0, color: '#666', fontSize: '0.9rem' }}>
                      Placed on: {new Date(order.order_date).toLocaleDateString()}
                    </p>
                    <p style={{ margin: '0.3rem 0 0 0', fontWeight: 'bold' }}>
                      Status: <span style={{ color: order.order_status === 'completed' ? 'green' : 'orange' }}>{order.order_status}</span>
                    </p>
                  </div>
                  
                  <button
                    onClick={() => toggleOrderDetails(order.id)}
                    style={{
                      backgroundColor: '#00adb5', color: 'white', border: 'none',
                      borderRadius: '4px', padding: '0.5rem 1rem', cursor: 'pointer'
                    }}
                  >
                    {isExpanded ? 'Hide Details ▲' : 'View Details ▼'}
                  </button>
                </div>

                {/* Granular inner line items sub-menu */}
                {isLoadingDetails && (
                  <p style={{ margin: '1rem 0 0 0', color: '#666' }}>Fetching items...</p>
                )}

                {isExpanded && expandedOrders[order.id] && (
                  <div style={{ 
                    marginTop: '1rem', 
                    paddingTop: '1rem', 
                    borderTop: '1px dashed #ccc',
                    backgroundColor: '#fff',
                    padding: '1rem',
                    borderRadius: '4px'
                  }}>
                    <h4 style={{ margin: '0 0 0.5rem 0' }}>Items in Order:</h4>
                    {expandedOrders[order.id].map((item, index) => (
                      <div key={index} style={{ 
                        display: 'flex', 
                        justifyContent: 'space-between', 
                        padding: '0.4rem 0',
                        borderBottom: index === expandedOrders[order.id].length - 1 ? 'none' : '1px solid #eee'
                      }}>
                        <span>{item.product_name} <span style={{ color: '#666' }}>x{item.quantity}</span></span>
                        <span style={{ fontWeight: 'bold' }}>
                          ${(Number(item.price_at_purchase) * item.quantity).toFixed(2)}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
