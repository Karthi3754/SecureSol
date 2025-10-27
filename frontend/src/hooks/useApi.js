import { useState, useEffect } from 'react';
import api from '../lib/axios';

export const useApi = (url, options = {}) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!url) return;

    const fetchData = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await api.get(url, options);
        
        // ✅ FIXED: Extract nested data if it exists
        const responseData = response.data;
        if (responseData && responseData.success && responseData.data) {
          setData(responseData.data); // Extract the nested data
        } else {
          setData(responseData); // Use response as-is
        }
      } catch (err) {
        setError(err.response?.data?.message || err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [url]);

  const refetch = async () => {
    if (!url) return;
    
    try {
      setLoading(true);
      setError(null);
      const response = await api.get(url, options);
      
      // ✅ FIXED: Same data extraction logic
      const responseData = response.data;
      let extractedData;
      if (responseData && responseData.success && responseData.data) {
        extractedData = responseData.data;
      } else {
        extractedData = responseData;
      }
      
      setData(extractedData);
      return extractedData;
    } catch (err) {
      setError(err.response?.data?.message || err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  return { data, loading, error, refetch };
};

export const useMutation = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const mutate = async (request) => {
    try {
      setLoading(true);
      setError(null);
      const response = await request();
      return response; 
    } catch (err) {
      setError(err.response?.data?.message || err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  return { mutate, loading, error };
};
