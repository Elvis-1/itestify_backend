from rest_framework.response import Response

class CustomResponse:
    def success(message, data=None, status_code=200):
        response = {
            'success': True,
            'message': message,
            'data': data
        }

        response.pop('data', None) if data is None else ...
        return Response(data=response, status=status_code)
    
    def error(message, err_code, data=None, status_code=400):
        response = {
            'success': False,
            'message': message,
            'code': err_code,
            'data': data
        }
        
        response.pop("data", None) if data is None else ...
        return Response(data=response, status=status_code)