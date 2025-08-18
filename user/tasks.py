
# All will be accomplished using celery.

# logics

# Before performing the checks we need to be sure that the invitation_status is not set to USED
# if created_at and updated_at are the same
    # we check using the created_at field - 

    # The check is if the difference between the created_at and the current time is greater than 30 mins per se
    # Then we change the invitation_status field to EXPIRED

# else if the updated_at is greater than the created_at
    # we do the check using the updated_at field.


# or if they don't want to use the background one due to inconsistencies

# I can just give them an endpoint to check if the token is still valid or not