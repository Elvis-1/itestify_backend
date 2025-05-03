# from django.test import TestCase
# from django.urls import reverse
# from rest_framework.test import APIClient
# from rest_framework import status
# from user.models import User
# from .models import Review

# class ReviewCreationTest(TestCase):
#     def setUp(self):
#         self.client = APIClient()
#         self.user = User.objects.create_user(
#             email='testuser@example.com',
#             password='testpass123'
#         )
#         self.url = reverse('review-create')

#     def test_authenticated_user_can_create_review(self):
#         """Test that an authenticated user can successfully create a review"""
#         self.client.force_authenticate(user=self.user)
        
#         # Test data with valid rating
#         data = {
#             'rating': 4,
#             'message': 'Great experience!'
#         }
        
#         response = self.client.post(self.url, data, format='json')
        
#         # Assert the response status code
#         self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
#         # Assert the review was created in database
#         self.assertEqual(Review.objects.count(), 1)
        
#         # Assert the response data matches what we sent
#         review = Review.objects.first()
#         self.assertEqual(response.data['id'], review.id)
#         self.assertEqual(response.data['rating'], data['rating'])
#         self.assertEqual(response.data['message'], data['message'])
#         self.assertEqual(response.data['user_email'], self.user.email)
        
#         # Assert the user was automatically set correctly
#         self.assertEqual(review.user.id, self.user.id)






# from django.test import TestCase
# from django.urls import reverse
# from rest_framework.test import APIClient
# from rest_framework import status
# from django.utils import timezone
# from datetime import timedelta
# from user.models import User
# from .models import Review

# class AdminReviewListTest(TestCase):
#     def setUp(self):
#         self.client = APIClient()
#         self.admin = User.objects.create_superuser(
#             email='admin@example.com',
#             password='adminpass123'
#         )
#         self.regular_user = User.objects.create_user(
#             email='user@example.com',
#             password='userpass123'
#         )
#         self.other_user = User.objects.create_user(
#             email='other@example.com',
#             password='otherpass123'
#         )
        
#         # Clear any existing reviews first
#         Review.objects.all().delete()
        
#         # Create test reviews with explicit timestamps
#         self.review1 = Review.objects.create(
#             user=self.regular_user,
#             rating=5,
#             message='Excellent service',
#             created_at=timezone.now() - timedelta(days=2)
#         )
#         self.review2 = Review.objects.create(
#             user=self.regular_user,
#             rating=3,
#             message='Average experience',
#             created_at=timezone.now() - timedelta(days=1)
#         )
#         self.review3 = Review.objects.create(
#             user=self.other_user,
#             rating=1,
#             message='Very poor',
#             created_at=timezone.now()
#         )
        
#         self.url = reverse('admin-review-list')

#     def test_admin_can_list_all_reviews(self):
#         """Test that admin can retrieve all reviews"""
#         self.client.force_authenticate(user=self.admin)
        
#         response = self.client.get(self.url)
        
#         # Assert successful response
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
        
#         # Parse the response data properly
#         response_data = response.json()
        
#         # Assert correct number of reviews are returned
#         self.assertEqual(len(response_data['results']), 3)  # Changed to look at 'results'
        
#         # Assert default ordering (most recent first)
#         self.assertEqual(response_data['results'][0]['id'], self.review3.id)
#         self.assertEqual(response_data['results'][1]['id'], self.review2.id)
#         self.assertEqual(response_data['results'][2]['id'], self.review1.id)
        
#         # Assert response contains all expected fields
#         for review in response_data['results']:
#             self.assertIn('id', review)
#             self.assertIn('user', review)
#             self.assertIn('user_email', review)
#             self.assertIn('rating', review)
#             self.assertIn('message', review)
#             self.assertIn('created_at', review)

#     def test_admin_list_contains_correct_user_info(self):
#         """Test that the review list contains correct user information"""
#         self.client.force_authenticate(user=self.admin)
        
#         response = self.client.get(self.url)
#         response_data = response.json()
        
#         # Find reviews in the response
#         review3_data = next(
#             r for r in response_data['results'] 
#             if r['id'] == self.review3.id
#         )
#         self.assertEqual(review3_data['user_email'], 'other@example.com')
        
#         review1_data = next(
#             r for r in response_data['results'] 
#             if r['id'] == self.review1.id
#         )
#         self.assertEqual(review1_data['user_email'], 'user@example.com')

#     def test_non_admin_cannot_access_list(self):
#         """Test that regular users can't access the admin review list"""
#         self.client.force_authenticate(user=self.regular_user)
#         response = self.client.get(self.url)
#         self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

#     def test_unauthenticated_cannot_access_list(self):
#         """Test that unauthenticated users can't access the admin review list"""
#         response = self.client.get(self.url)
#         self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)



# from django.test import TestCase
# from django.urls import reverse
# from rest_framework.test import APIClient
# from rest_framework import status
# from django.utils import timezone
# from datetime import timedelta, datetime
# from user.models import User
# from .models import Review

# class AdminReviewFilterTest(TestCase):
#     def setUp(self):
#         self.client = APIClient()
#         self.admin = User.objects.create_superuser(
#             email='admin@example.com',
#             password='adminpass123'
#         )
        
#         # Clear any existing reviews
#         Review.objects.all().delete()
        
#         # Create test data with specific dates and ratings
#         now = timezone.now()
#         self.today = now.date()
#         self.yesterday = (now - timedelta(days=1)).date()
#         self.last_week = (now - timedelta(days=7)).date()
        
#         # Reviews with different ratings and dates
#         self.review1 = Review.objects.create(
#             user=self.admin,
#             rating=5,
#             message='Excellent',
#             created_at=now - timedelta(days=1)  # Yesterday
#         )
#         self.review2 = Review.objects.create(
#             user=self.admin,
#             rating=3,
#             message='Average',
#             created_at=now - timedelta(days=3)  # 3 days ago
#         )
#         self.review3 = Review.objects.create(
#             user=self.admin,
#             rating=1,
#             message='Poor',
#             created_at=now - timedelta(days=5)  # 5 days ago
#         )
#         self.review4 = Review.objects.create(
#             user=self.admin,
#             rating=5,
#             message='Great',
#             created_at=now  # Today
#         )
        
#         self.url = reverse('admin-review-list')
#         self.client.force_authenticate(user=self.admin)

#     def test_filter_by_exact_rating(self):
#         """Test filtering reviews by exact rating"""
#         response = self.client.get(self.url, {'rating': 5})
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         data = response.json()
        
#         self.assertEqual(len(data['results']), 2)
#         for review in data['results']:
#             self.assertEqual(review['rating'], 5)

#     def test_filter_by_rating_range(self):
#         """Test filtering reviews by rating range"""
#         # Ratings greater than or equal to 3
#         response = self.client.get(self.url, {'rating__gte': 3})
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         data = response.json()
        
#         self.assertEqual(len(data['results']), 3)
#         for review in data['results']:
#             self.assertGreaterEqual(review['rating'], 3)

#         # Ratings less than or equal to 3
#         response = self.client.get(self.url, {'rating__lte': 3})
#         data = response.json()
#         self.assertEqual(len(data['results']), 2)
#         for review in data['results']:
#             self.assertLessEqual(review['rating'], 3)

#     def test_filter_by_exact_date(self):
#         """Test filtering reviews by exact date"""
#         date_str = self.yesterday.isoformat()
#         response = self.client.get(self.url, {'created_at__date': date_str})
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         data = response.json()
        
#         self.assertEqual(len(data['results']), 1)
#         self.assertEqual(data['results'][0]['id'], self.review1.id)

#     def test_invalid_date_filter(self):
#         """Test invalid date filter format"""
#         response = self.client.get(self.url, {'created_at__date': 'invalid-date'})
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)





from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from django.utils import timezone
from datetime import timedelta
from user.models import User
from .models import Review

class AdminReviewFilterTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin = User.objects.create_superuser(
            email='admin@example.com',
            password='adminpass123'
        )
        
        # Clear any existing reviews
        Review.objects.all().delete()
        
        # Create test data with specific dates and ratings
        now = timezone.now()
        self.now = now
        self.today = now.date()
        self.yesterday = (now - timedelta(days=1)).date()
        self.three_days_ago = (now - timedelta(days=3)).date()
        self.five_days_ago = (now - timedelta(days=5)).date()
        self.last_week = (now - timedelta(days=7)).date()
        
        # Create reviews with precise timestamps
        self.review1 = Review.objects.create(  # Yesterday
            user=self.admin,
            rating=5,
            message='Excellent',
            created_at=now - timedelta(days=1)
        )
        self.review2 = Review.objects.create(  # 3 days ago
            user=self.admin,
            rating=3,
            message='Average',
            created_at=now - timedelta(days=3)
        )
        self.review3 = Review.objects.create(  # 5 days ago
            user=self.admin,
            rating=1,
            message='Poor',
            created_at=now - timedelta(days=5)
        )
        self.review4 = Review.objects.create(  # Today
            user=self.admin,
            rating=5,
            message='Great',
            created_at=now
        )
        
        self.url = reverse('admin-review-list')
        self.client.force_authenticate(user=self.admin)

    def test_filter_by_date_range(self):
        """Test filtering reviews by date range"""
        # Should include reviews from yesterday (review1), 3 days ago (review2), and today (review4)
        response = self.client.get(self.url, {
            'created_at__gte': (self.now - timedelta(days=4)).isoformat(),
            'created_at__lte': self.now.isoformat()
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        
        self.assertEqual(len(data['results']), 3)
        returned_ids = {r['id'] for r in data['results']}
        expected_ids = {self.review1.id, self.review2.id, self.review4.id}
        self.assertEqual(returned_ids, expected_ids)

    def test_combined_rating_and_date_filters(self):
        """Test combining rating and date filters"""
        # Should get reviews with rating >=3 from last week to yesterday
        response = self.client.get(self.url, {
            'rating__gte': 3,
            'created_at__gte': (self.now - timedelta(days=7)).isoformat(),
            'created_at__lte': (self.now - timedelta(days=1)).isoformat()
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        
        self.assertEqual(len(data['results']), 2)
        returned_ids = {r['id'] for r in data['results']}
        expected_ids = {self.review1.id, self.review2.id}
        self.assertEqual(returned_ids, expected_ids)