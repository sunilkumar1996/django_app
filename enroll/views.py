from django.shortcuts import render, HttpResponseRedirect
# from django.contrib.auth.forms import UserCreationForm
from .forms import SignUpForm
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm, SetPasswordForm
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash


# Signup view Function
def sign_up(request):
    if request.method == 'POST':
        # form = UserCreationForm(request.POST)
        form = SignUpForm(request.POST)
        if form.is_valid():
            messages.success(request, 'Account Created Successfully !!')
            form.save()
    else:
        # form = UserCreationForm()
        form = SignUpForm()
    return render(request, 'enroll/signup.html', {'form': form})


# Login view Function here
def user_login(request):
    if not request.user.is_authenticated:
        if request.method == 'POST':
            form = AuthenticationForm(request=request, data=request.POST)
            if form.is_valid():
                uname = form.cleaned_data['username']
                upass = form.cleaned_data['password']
                user = authenticate(username=uname, password=upass)
                if user is not None:
                    messages.success(request, 'Logged is Successfull !!')
                    login(request, user)
                    return HttpResponseRedirect('/profile/')
        else:
            form = AuthenticationForm()
        return render(request, 'enroll/userlogin.html', {'form': form})
    else:
        return HttpResponseRedirect('/profile/')


# Profile view function here
def user_profile(request):
    if request.user.is_authenticated:
        return render(request, 'enroll/profile.html', {'name': request.user})
    else:
        return HttpResponseRedirect('/login/')


# Logout view function here.
def user_logout(request):
    logout(request)
    return HttpResponseRedirect('/login/')


# Change Password with old password
def user_change_pass(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            form = PasswordChangeForm(user=request.user, data=request.POST)
            if form.is_valid():
                form.save()
                update_session_auth_hash(request, form.user)
                messages.success(request, 'Password Changed Successfully !!')
                return HttpResponseRedirect('/profile/')
        else:
            form = PasswordChangeForm(user=request.user)
        return render(request, 'enroll/changepass.html', {'form': form})
    else:
        return HttpResponseRedirect('/login/')


# Change Password without old password
def user_change_password(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            form = SetPasswordForm(user=request.user, data=request.POST)
            if form.is_valid():
                form.save()
                update_session_auth_hash(request, form.user)
                messages.success(request, 'Password changed Successfully !!!')
                return HttpResponseRedirect('/profile/')
        else:
            form = SetPasswordForm(user=request.user)
            return render(request, 'enroll/changepass1.html', {'form': form})
    else:
        return HttpResponseRedirect('/login/')
