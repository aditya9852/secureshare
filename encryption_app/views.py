from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import HttpResponse
from django.db import models,IntegrityError
from django.db.models import Q
from .models import EncryptedFile, FileShare,UserRelation
from .forms import EncryptionForm, DecryptionForm, FriendFileShareForm
from Crypto.Cipher import DES3
from hashlib import md5
from django.contrib.auth.models import User
from app1.models import UserRelation  # Make sure to import from app1
import zlib
import os
from django.http import JsonResponse, HttpResponseForbidden
from django.contrib.auth import get_user_model

User = get_user_model()
@login_required(login_url="auth/login")
def filesharing_home(request):
    """Home view showing recent files and forms"""
    # Get recent files - both owned and shared
    recent_files = EncryptedFile.objects.filter(
        models.Q(user=request.user) | 
        models.Q(shared_with=request.user)
    ).select_related('user').order_by('-uploaded_at')[:5]
    
    encryption_form = EncryptionForm()
    decryption_form = DecryptionForm()
    
    context = {
        'recent_files': recent_files,
        'encryption_form': encryption_form,
        'decryption_form': decryption_form,
    }
    return render(request, 'encryption_app/fileshare_home.html', context)

@login_required(login_url="auth/login")
def encrypt_file(request):
    """Handle file encryption"""
    if request.method == 'POST':
        form = EncryptionForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            key = form.cleaned_data['encryption_key']
            
            try:
                # Generate key
                key_hash = md5(key.encode('ascii')).digest()
                tdes_key = DES3.adjust_key_parity(key_hash)
                cipher = DES3.new(tdes_key, DES3.MODE_EAX)
                
                # Read and compress file
                file_bytes = uploaded_file.read()
                compressed_bytes = zlib.compress(file_bytes)
                
                # Encrypt
                nonce = cipher.nonce
                encrypted_bytes = cipher.encrypt(compressed_bytes)
                
                # Save to database
                encrypted_file = EncryptedFile(
                    filename=uploaded_file.name,
                    file_extension=os.path.splitext(uploaded_file.name)[1],
                    file_bytes=nonce + encrypted_bytes,
                    user=request.user
                )
                encrypted_file.save()
                
                messages.success(request, 'File encrypted successfully!')
                return redirect('file_list')
            except Exception as e:
                messages.error(request, f'Encryption failed: {str(e)}')
    else:
        form = EncryptionForm()
    
    return render(request, 'encryption_app/encrypt.html', {'form': form})

@login_required(login_url="auth/login")
def decrypt_file(request):
    """Handle file decryption"""
    if request.method == 'POST':
        form = DecryptionForm(request.POST)
        if form.is_valid():
            filename = form.cleaned_data['filename']
            key = form.cleaned_data['encryption_key']
            
            try:
                # Updated query to check both owned and shared files
                encrypted_file = EncryptedFile.objects.filter(
                    models.Q(user=request.user) | 
                    models.Q(shared_with=request.user),
                    filename=filename
                ).first()
                
                if not encrypted_file:
                    raise EncryptedFile.DoesNotExist
                
                # Generate the TDES key
                key_hash = md5(key.encode('ascii')).digest()
                tdes_key = DES3.adjust_key_parity(key_hash)

                # Extract nonce and encrypted data
                encrypted_bytes = encrypted_file.file_bytes
                nonce = encrypted_bytes[:16]  # First 16 bytes are nonce
                encrypted_data = encrypted_bytes[16:]  # Remaining data is encrypted content

                # Decrypt the file data
                cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=nonce)
                decrypted_data = cipher.decrypt(encrypted_data)

                # Check if the data is compressed
                is_compressed = decrypted_data[:2] in [b'x\x9c', b'x\xda', b'x\x01']
                
                if is_compressed:
                    try:
                        final_data = zlib.decompress(decrypted_data)
                    except zlib.error as e:
                        raise ValueError(f"Decompression failed: {e}")
                else:
                    final_data = decrypted_data

                # Validate decrypted content
                if not final_data:
                    raise ValueError("Decryption resulted in empty content")

                # Prepare response
                response = HttpResponse(
                    final_data,
                    content_type='application/octet-stream'
                )
                response['Content-Disposition'] = f'attachment; filename=decrypted_{filename}'
                return response
            
            except EncryptedFile.DoesNotExist:
                messages.error(request, 'File not found')
            except ValueError as ve:
                messages.error(request, str(ve))
                print(f"Decryption error details: {ve}")
            except Exception as e:
                messages.error(request, f'Decryption failed: {str(e)}')
                print(f"Unexpected error during decryption: {str(e)}")
    else:
        form = DecryptionForm()
        # Pre-fill filename if provided in GET parameters
        filename = request.GET.get('filename')
        if filename:
            form = DecryptionForm(initial={'filename': filename})

    return render(request, 'encryption_app/decrypt.html', {'form': form})

@login_required(login_url="auth/login")
def share_file(request, file_id):
    """
    Share an encrypted file with a friend (only friends from app1).
    Uses FileShare through model and correct relationship fields.
    """
    if request.method == 'GET':
        # Get the encrypted file that the user owns
        encrypted_file = get_object_or_404(EncryptedFile, id=file_id, user=request.user)
        
        # Debug print for encrypted file
        print(f"Found encrypted file: {encrypted_file.id} owned by user: {request.user.id}")
        
        # Get friends from both directions of the relationship
        friends_query = User.objects.filter(
            models.Q(
                friend_relations_app1__user=request.user,
                friend_relations_app1__accepted=True
            ) |
            models.Q(
                user_relations_app1__friend=request.user,
                user_relations_app1__accepted=True
            )
        ).distinct()
        
        # Debug prints for friendship query
        print(f"SQL Query for friends: {friends_query.query}")
        friends_list = list(friends_query)
        print(f"Friends found: {[f.username for f in friends_list]}")
        
        # Get existing shares
        existing_shares = FileShare.objects.filter(file=encrypted_file)
        print(f"Existing shares: {[share.shared_with.username for share in existing_shares]}")
        
        # Get available friends
        available_friends = friends_query.exclude(
            id__in=existing_shares.values_list('shared_with_id', flat=True)
        )
        
        print(f"Available friends: {[f.username for f in available_friends]}")
        
        context = {
            'file': encrypted_file,
            'friends': available_friends,
            'has_friends': available_friends.exists(),
            'debug_friend_count': available_friends.count()
        }
        
        return render(request, 'encryption_app/share_file.html', context)
    
    elif request.method == 'POST':
        try:
            encrypted_file = get_object_or_404(EncryptedFile, id=file_id, user=request.user)
            friend_id = request.POST.get('friend_id')
            
            if not friend_id:
                return JsonResponse({'error': 'Friend ID is required'}, status=400)
            
            # Updated to use app1's UserRelation model and its fields
            friend_relation = UserRelation.objects.filter(
                models.Q(
                    models.Q(user=request.user, friend_id=friend_id) |
                    models.Q(friend=request.user, user_id=friend_id)
                ),
                accepted=True
            ).first()
            
            if not friend_relation:
                return JsonResponse({'error': 'Friend relationship not found'}, status=400)
            
            friend = get_object_or_404(User, id=friend_id)
            
            # Create FileShare record
            try:
                FileShare.objects.create(
                    file=encrypted_file,
                    shared_with=friend
                )
                
                
                return JsonResponse({
                    'success': True,
                    'message': f'File shared successfully with {friend.username}'
                })
                
            except IntegrityError:
                return JsonResponse({
                    'error': f'File has already been shared with {friend.username}'
                }, status=400)
                
        except Exception as e:
            print(f"Error in share_file POST: {str(e)}")
            return JsonResponse({
                'error': str(e)
            }, status=400)

@login_required(login_url="auth/login")
def file_list(request):
    """View for listing all files with sharing functionality"""
    # Get files owned by the user
    owned_files = EncryptedFile.objects.filter(user=request.user)
    # Get files shared with the user
    shared_files = EncryptedFile.objects.filter(shared_with=request.user)
    
    context = {
        'owned_files': owned_files,
        'shared_files': shared_files,
    }
    return render(request, 'encryption_app/file_list.html', context)




@login_required(login_url="auth/login")
def download_encrypted_file(request, file_id):
    """Download the encrypted file directly"""
    # Check if user has access to the file
    encrypted_file = get_object_or_404(
        EncryptedFile.objects.filter(
            models.Q(user=request.user) | models.Q(shared_with=request.user)
        ),
        id=file_id
    )
    
    response = HttpResponse(
        encrypted_file.file_bytes,
        content_type='application/octet-stream'
    )
    response['Content-Disposition'] = f'attachment; filename=encrypted_{encrypted_file.filename}'
    return response

@login_required(login_url="auth/login")
def revoke_access(request, file_id, user_id):
    """Revoke file access from a user"""
    file = get_object_or_404(EncryptedFile, id=file_id, user=request.user)
    
    try:
        file_share = FileShare.objects.get(file=file, shared_with_id=user_id)
        file_share.delete()
        messages.success(request, 'File access revoked successfully')
    except FileShare.DoesNotExist:
        messages.error(request, 'Share record not found')
    
    return redirect('file_list')