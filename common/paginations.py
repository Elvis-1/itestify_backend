from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class StandardResultsSetPagination(PageNumberPagination):
    """
    Custom pagination class that extends PageNumberPagination to include additional
    metadata in the paginated response.

    Attributes:
        page_size (int): Default number of items per page.
        page_size_query_param (str): The name of the query parameter used to set the page size.
        max_page_size (int): The maximum number of items allowed per page.
    """

    page_size = 100
    page_size_query_param = "page_size"
    max_page_size = 100

    def get_paginated_response(self, data):
        """
        Constructs a paginated response including metadata about the pagination.

        Args:
            data (list): The data to include in the paginated response.

        Returns:
            Response: A Response object with metadata and the paginated data.
        """
        current_page = self.page.number
        total_pages = self.page.paginator.num_pages
        return Response(
            {
                "success": True,
                "message": "Success",
                "data": {
                    "pagination" : {
                    "count": self.page.paginator.count,
                    "next": self.get_next_link(),
                    "previous": self.get_previous_link(),
                    "current_page": current_page,
                    "total_pages": total_pages,
                    },
                    "paginated_data": data
                 
                },
                
            }
        )

