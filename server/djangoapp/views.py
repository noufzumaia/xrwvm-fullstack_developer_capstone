from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
import json
import logging

from .models import CarMake, CarModel
from .restapis import get_request, analyze_review_sentiments, post_review
from .populate import initiate

# Get an instance of a logger
logger = logging.getLogger(__name__)

@csrf_exempt
def login_user(request):
    data = json.loads(request.body)
    username = data["userName"]
    password = data["password"]
    user = authenticate(username=username, password=password)
    
    if user is not None:
        login(request, user)
        data = {"userName": username, "status": "Authenticated"}
    else:
        data = {"userName": username, "status": "Unauthenticated"}
    
    return JsonResponse(data)

def logout_request(request):
    logout(request)
    return JsonResponse({"userName": ""})

@csrf_exempt
def registration(request):
    data = json.loads(request.body)
    username = data["userName"]
    password = data["password"]
    first_name = data["firstName"]
    last_name = data["lastName"]
    email = data["email"]

    if User.objects.filter(username=username).exists():
        return JsonResponse({"status": "User already exists"})

    user = User.objects.create_user(
        username=username,
        first_name=first_name,
        last_name=last_name,
        password=password,
        email=email,
    )
    login(request, user)
    return JsonResponse({"userName": username, "status": "Authenticated"})

def get_cars(request):
    if CarMake.objects.count() == 0:
        initiate()
    car_models = CarModel.objects.select_related("car_make")
    cars = [{"CarModel": car_model.name, "CarMake": car_model.car_make.name} for car_model in car_models]
    return JsonResponse({"CarModels": cars})

def get_dealerships(request, state="All"):
    endpoint = "/fetchDealers" if state == "All" else f"/fetchDealers/{state}"
    dealerships = get_request(endpoint)
    return JsonResponse({"status": 200, "dealers": dealerships})

def get_dealer_reviews(request, dealer_id):
    if dealer_id:
        endpoint = f"/fetchReviews/dealer/{dealer_id}"
        reviews = get_request(endpoint)
        for review_detail in reviews:
            response = analyze_review_sentiments(review_detail["review"])
            review_detail["sentiment"] = response["sentiment"]
        return JsonResponse({"status": 200, "reviews": reviews})
    return JsonResponse({"status": 400, "message": "Bad Request"})

def get_dealer_details(request, dealer_id):
    if dealer_id:
        endpoint = f"/fetchDealer/{dealer_id}"
        dealership = get_request(endpoint)
        return JsonResponse({"status": 200, "dealer": dealership})
    return JsonResponse({"status": 400, "message": "Bad Request"})

def add_review(request):
    if request.user.is_anonymous is False:
        data = json.loads(request.body)
        try:
            # Assuming the post_review function is defined correctly
            post_review(data)
            return JsonResponse({"status": 200})
        except Exception as err:
            return JsonResponse({"status": 401, "message": f"Error in posting review: {str(err)}"})
    return JsonResponse({"status": 403, "message": "Unauthorized"})

def get_inventory(request, dealer_id):
    data = request.GET
    if dealer_id:
        endpoint = "/cars/"
        if 'year' in data:
            endpoint += f"carsbyyear/{dealer_id}/{data['year']}"
        elif 'make' in data:
            endpoint += f"carsbymake/{dealer_id}/{data['make']}"
        elif 'model' in data:
            endpoint += f"carsbymodel/{dealer_id}/{data['model']}"
        elif 'mileage' in data:
            endpoint += f"carsbymaxmileage/{dealer_id}/{data['mileage']}"
        elif 'price' in data:
            endpoint += f"carsbyprice/{dealer_id}/{data['price']}"

        cars = get_request(endpoint)
        return JsonResponse({"status": 200, "cars": cars})
    return JsonResponse({"status": 400, "message": "Bad Request"})
