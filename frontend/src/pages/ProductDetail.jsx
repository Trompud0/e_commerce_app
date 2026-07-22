import { useState, useEffect, useContext } from 'react';
import { useParams, Link } from 'react-router-dom';
import { CartContext } from './CartContext';
import axios from 'axios';

function ProductDetail() {
  // This hook grabs the variable :id parameter from your App.jsx route path string
  const { id } = useParams(); 

  const { addToCart } = useContext(CartContext);
  
  const [product, setProduct] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchSingleProduct = async () => {
      try {
        setLoading(true);

        const response = await axios.get(`http://localhost:3000/products/${id}`);
        setProduct(response.data);

        setLoading(false);
      } catch (err) {
        setError('Could not locate item specifications.');
        setLoading(false);
      }
    };

    fetchSingleProduct();
  }, [id]); 

  if (loading) return <div style={{ textAlign: 'center', marginTop: '3rem' }}>Fetching full product details...</div>;
  if (error) return <div style={{ textAlign: 'center', color: 'red', marginTop: '3rem' }}>{error}</div>;
  if (!product) return null;

  return (
    <div style={{ maxWidth: '800px', margin: '2rem auto', display: 'flex', gap: '2rem', padding: '1rem' }}>
      {product.image_url && (
        <img 
          src={product.image_url} 
          alt={product.product_name} 
          style={{ width: '400px', height: '400px', objectFit: 'cover', borderRadius: '8px' }} 
        />
      )}
      
      <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
        <h2>{product.product_name}</h2>
        <p style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#00adb5', margin: '0.5rem 0' }}>
          ${Number(product.price).toFixed(2)}
        </p>
        <p style={{ lineHeight: '1.6', color: '#555', marginBottom: '1.5rem' }}>{product.description}</p>
        <p style={{ fontSize: '0.9rem', color: '#888' }}>In Stock: {product.stock_quantity} units</p>
        
      {/* Conditional Rendering: Check if user has a token session active */}
      {localStorage.getItem('token') ? (
        <button 
          onClick={() => addToCart(product.id, 1)} 
          style={{
            marginTop: '1.5rem', padding: '0.8rem 1.5rem', backgroundColor: '#333',
            color: 'white', border: 'none', borderRadius: '4px', fontWeight: 'bold', cursor: 'pointer'
          }}
        >
        Add to Cart 🛒
        </button>
      ) : (
        <div style={{ marginTop: '1.5rem', padding: '1rem', backgroundColor: '#f9f9f9', border: '1px dashed #ccc', borderRadius: '4px' }}>
          <p style={{ margin: 0, color: '#666', fontSize: '0.9rem' }}>
            Want to buy this item? <Link to="/login" style={{ color: '#00adb5', fontWeight: 'bold' }}>Log in</Link> or <Link to="/register" style={{ color: '#00adb5', fontWeight: 'bold' }}>Create an account</Link> to start shopping!
          </p>
        </div>
      )}

        <Link to="/" style={{ marginTop: '1.5rem', color: '#333', textDecoration: 'underline' }}>
          ← Back to All Products
        </Link>
      </div>
    </div>
  );
}

export default ProductDetail;
