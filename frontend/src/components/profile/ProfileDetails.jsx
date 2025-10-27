import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  User, 
  Mail, 
  Edit3, 
  Save, 
  X, 
  AlertCircle,
  CheckCircle 
} from 'lucide-react';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Label } from '../ui/Label';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { useAuth } from '../../hooks/useAuth';
import { useMutation } from '../../hooks/useApi';
import { userService } from '../../services/userService';

const ProfileDetails = () => {
  const { user, updateUser } = useAuth();
  const [isEditing, setIsEditing] = useState(false);
  const [formData, setFormData] = useState({
    username: user?.username || '',
    email: user?.email || ''
  });
  const [errors, setErrors] = useState({});
  const [successMessage, setSuccessMessage] = useState('');

  const { mutate, loading, error } = useMutation();

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.username || formData.username.length < 3) {
      newErrors.username = 'Username must be at least 3 characters';
    }
    
    if (!formData.email || !/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleEdit = () => {
    setIsEditing(true);
    setFormData({
      username: user?.username || '',
      email: user?.email || ''
    });
    setErrors({});
    setSuccessMessage('');
  };

  const handleCancel = () => {
    setIsEditing(false);
    setFormData({
      username: user?.username || '',
      email: user?.email || ''
    });
    setErrors({});
  };

  const handleSave = async () => {
    if (!validateForm()) return;

    try {
      const updatedUser = await mutate(() => 
        userService.updateProfile(formData)
      );
      
      updateUser(updatedUser);
      setIsEditing(false);
      setSuccessMessage('Profile updated successfully!');
      
      setTimeout(() => setSuccessMessage(''), 3000);
    } catch (err) {
      console.error('Failed to update profile:', err);
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <User className="h-5 w-5" />
            Profile Information
          </CardTitle>
          {!isEditing && (
            <Button
              variant="outline"
              size="sm"
              onClick={handleEdit}
              className="flex items-center gap-2"
            >
              <Edit3 className="h-4 w-4" />
              Edit Profile
            </Button>
          )}
        </div>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {/* Success Message */}
        {successMessage && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-3 bg-green-50 border border-green-200 rounded-md flex items-center gap-2 text-green-600"
          >
            <CheckCircle className="h-4 w-4" />
            <span className="text-sm">{successMessage}</span>
          </motion.div>
        )}

        {/* Error Message */}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-3 bg-red-50 border border-red-200 rounded-md flex items-center gap-2 text-red-600"
          >
            <AlertCircle className="h-4 w-4" />
            <span className="text-sm">{error}</span>
          </motion.div>
        )}

        {/* Profile Form */}
        <div className="space-y-4">
          {/* Username Field */}
          <div className="space-y-2">
            <Label htmlFor="username">Username</Label>
            {isEditing ? (
              <Input
                id="username"
                name="username"
                value={formData.username}
                onChange={handleChange}
                placeholder="Enter your username"
                className={errors.username ? 'border-red-500' : ''}
              />
            ) : (
              <div className="p-3 bg-gray-50 border rounded-md">
                <span className="text-gray-900">{user?.username}</span>
              </div>
            )}
            {errors.username && (
              <p className="text-sm text-red-500">{errors.username}</p>
            )}
          </div>

          {/* Email Field */}
          <div className="space-y-2">
            <Label htmlFor="email">Email Address</Label>
            {isEditing ? (
              <Input
                id="email"
                name="email"
                type="email"
                value={formData.email}
                onChange={handleChange}
                placeholder="Enter your email"
                className={errors.email ? 'border-red-500' : ''}
              />
            ) : (
              <div className="p-3 bg-gray-50 border rounded-md flex items-center gap-2">
                <Mail className="h-4 w-4 text-gray-500" />
                <span className="text-gray-900">{user?.email}</span>
              </div>
            )}
            {errors.email && (
              <p className="text-sm text-red-500">{errors.email}</p>
            )}
          </div>

          {/* Account Stats */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t">
            <div className="text-center p-4 bg-blue-50 border border-blue-200 rounded-lg">
              <div className="text-2xl font-bold text-blue-600">
                {user?.totalScans || 0}
              </div>
              <div className="text-sm text-blue-700">Total Scans</div>
            </div>
            <div className="text-center p-4 bg-green-50 border border-green-200 rounded-lg">
              <div className="text-2xl font-bold text-green-600">
                {user?.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'N/A'}
              </div>
              <div className="text-sm text-green-700">Member Since</div>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        {isEditing && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex gap-3 pt-4 border-t"
          >
            <Button
              onClick={handleSave}
              disabled={loading}
              className="flex-1"
            >
              {loading ? (
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                  Saving...
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <Save className="h-4 w-4" />
                  Save Changes
                </div>
              )}
            </Button>
            <Button
              variant="outline"
              onClick={handleCancel}
              disabled={loading}
              className="flex-1"
            >
              <X className="h-4 w-4 mr-2" />
              Cancel
            </Button>
          </motion.div>
        )}
      </CardContent>
    </Card>
  );
};

export default ProfileDetails;
