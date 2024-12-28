from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import login
from .models import UserFaceImage
from .utils import base64_file, prepare_image
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.contrib.auth import logout
from django.contrib.auth import authenticate
from .authenticate import FaceIdAuthBackend

def SignupPage(request):
    if request.user.is_authenticated:
        return redirect("login")
    
    error_message = ""

    if request.method == "POST":
        uname = request.POST.get("username")
        email = request.POST.get("email")
        pass1 = request.POST.get("password1")
        pass2 = request.POST.get("password2")
        face_image = request.POST.get("image")

        data = {
            "username": uname,
            "useremail": email,
        }

        # Validate face image
        if not face_image:
            return JsonResponse({
                'success': False,
                'error': "Face image is required",
                'step': 2
            })

        # Check if a user with the same email or username already exists
        if User.objects.filter(username=uname).exists():
            return JsonResponse({
                'success': False,
                'error': "A user with the same username already exists.",
                'step': 1
            })

        elif User.objects.filter(email=email).exists():
            return JsonResponse({
                'success': False,
                'error': "A user with the same email already exists.",
                'step': 1
            })

        try:
            # Create the user
            user = User.objects.create_user(username=uname, email=email, password=pass1)
            
            # Save face image
            face_image_file = base64_file(face_image)
            UserFaceImage.objects.create(user=user, image=face_image_file)
            
            # Log the user in after registration
            login(request, user)
            
            return JsonResponse({
                'success': True,
                'redirect_url': reverse('login')
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e),
                'step': 1
            })

    return render(request, "two_factor_face_auth/signup.html", {"error_message": error_message})


def LoginPage(request):
    if request.user.is_authenticated:
        return redirect("Home_page")
    
    error_message = ""
    email = ""
    
    if request.method == "POST":
        email = request.POST.get("email")
        pass1 = request.POST.get("pass")
        face_image = request.POST.get("image")
        
        try:
            curr_user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': "Email not found. Please check your Email."
            })

        # First authenticate with username/password
        user = authenticate(request, username=curr_user.username, password=pass1)
        
        if user is not None:
            # If face image is provided, verify it
            if face_image:
                face_image_data = prepare_image(face_image)
                face_id_auth = FaceIdAuthBackend()
                face_verified = face_id_auth.check_face_id(
                    face_id=user.userfaceimage.image,
                    uploaded_face_id=face_image_data
                )
                
                if face_verified:
                    login(request, user)
                    return JsonResponse({
                        'success': True,
                        'redirect_url': reverse('Home_page')
                    })
                else:
                    return JsonResponse({
                        'success': False,
                        'error': "Face verification failed. Please try again."
                    })
            else:
                return JsonResponse({
                    'success': False,
                    'error': "Face verification required."
                })
        else:
            error_message = "Incorrect password. Please try again."
            return JsonResponse({
                'success': False,
                'error': error_message
            })
    
    return render(
        request, "two_factor_face_auth/login.html", 
        {"error_message": error_message, "email": email}
    )

def LogoutPage(request):
    logout(request)
    return redirect("login")


def index(request):     
    return render(request, "two_factor_face_auth/index.html")

def Home_page(request):
    return render(request, "two_factor_face_auth/home.html")

def Home2(request):
    return render(request, "two_factor_face_auth/index.html")