from django.db import migrations

WATCHDOG_TASK_NAME = 'autonomous_loop_watchdog'


def seed_watchdog(apps, schema_editor):
    IntervalSchedule = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')

    schedule, _ = IntervalSchedule.objects.get_or_create(every=60, period='seconds')
    PeriodicTask.objects.get_or_create(
        name=WATCHDOG_TASK_NAME,
        defaults={
            'interval': schedule,
            'task': 'autonomous_loop_watchdog',
        },
    )


def unseed_watchdog(apps, schema_editor):
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    PeriodicTask.objects.filter(name=WATCHDOG_TASK_NAME).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('autonomousMode', '0001_initial'),
        ('django_celery_beat', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(seed_watchdog, unseed_watchdog),
    ]
